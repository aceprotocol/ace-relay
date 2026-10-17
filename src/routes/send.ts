import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { MAX_SEND_BODY_BYTES, checkPacketTime, decodePacket, sha256Hex } from '@ace-protocol/sdk';
import type { MessageStore } from '../store/messages.js';
import type { BlockStore } from '../store/blocks.js';
import type { DescriptorStore } from '../store/descriptors.js';
import { BUSY_RETRY_SECONDS, RelayError, relayBusy, sdk } from '../errors.js';
import { enforceRate, networkOf, permittedSubject, type RouteDeps } from './shared.js';

interface SendDeps extends RouteDeps {
  messageStore: MessageStore;
  blocks: BlockStore;
  descriptors: DescriptorStore;
  sseRegistry: { notify(aceId: string): Promise<number> };
  /** Present when the relay offers wake hints. */
  dispatcher?: { queued(aceId: string): void };
}
/**
 * The single answer to every send the relay refuses for admission: unknown, unregistered, non-public or blocking
 * recipient, and missing or invalid permit look the same, so a caller cannot enumerate private agents or block lists.
 */
const notPermitted = (): RelayError => new RelayError('not_permitted', 'not permitted');

const sendSchema = {
  body: {
    type: 'object',
    additionalProperties: false,
    required: ['packet'],
    properties: { packet: {}, permit: {} },
  },
} as const;

/**
 * 07 § Send. The relay never verifies the packet signature and needs no sender KEL: `from` is unauthenticated, so
 * everything keyed on it is bound either to a permit the recipient signed for `from`, or to the stranger allowance.
 */
export async function sendRoutes(app: FastifyInstance, deps: SendDeps): Promise<void> {
  const { identityStore, messageStore, blocks, descriptors, rateLimiter, config, clock } = deps;
  const full = (message?: string) => new RelayError('recipient_inbox_full', message, BUSY_RETRY_SECONDS);

  app.post('/v1/send', { bodyLimit: MAX_SEND_BODY_BYTES, schema: sendSchema }, async (req: FastifyRequest, reply: FastifyReply) => {
    const body = req.body as { packet: unknown; permit?: unknown };
    // 1. Decode and the acceptance window.
    const packet = sdk(() => decodePacket(body.packet));
    const now = clock();
    sdk(() => checkPacketTime(packet, now));
    const json = JSON.stringify(packet);
    const digest = sha256Hex(json);
    const [recipient, queued] = await Promise.all([identityStore.read(packet.to), messageStore.isQueued(packet.to, digest)]);
    if (!recipient) throw notPermitted();
    // 2. A byte-identical packet already queued is accepted again without enqueuing.
    if (queued) return { ok: true };
    // 3. Blocks win over permits and come before any bucket is charged; answered like every other refusal.
    if (await blocks.isBlocked(packet.to, packet.from)) throw notPermitted();
    const network = networkOf(req);
    let kind: 'normal' | 'stranger';
    if (body.permit !== undefined) {
      // 4. A permit issued by `to` to `from`, verified against `to`'s registered KEL at now.
      if (permittedSubject(recipient, body.permit, packet.from, now) === null) throw notPermitted();
      await enforceRate(rateLimiter, `send:${packet.to}:${packet.from}`, config.sendRateLimit, 60, 'identity');
      kind = 'normal';
    } else {
      // 5. The stranger allowance of a public recipient.
      const self = await descriptors.get(packet.to, now);
      if (self?.descriptor.visibility !== 'public') throw notPermitted();
      await enforceRate(rateLimiter, `stranger-ip:${network}`, config.strangerIpRateLimit, 3600, 'network');
      await enforceRate(rateLimiter, `stranger-to:${packet.to}`, config.strangerRecipientRateLimit, 3600, 'identity');
      kind = 'stranger';
    }
    const result = await messageStore.enqueue(packet.to, json, digest, kind, { sender: packet.from, network });
    switch (result.status) {
      case 'enqueued': {
        const listening = await deps.sseRegistry.notify(packet.to);
        // A wake only once the response is written (07 § Wake hints): neither the response nor its timing depends on
        // the recipient's registration.
        const { dispatcher } = deps;
        if (dispatcher && listening === 0) reply.raw.once('finish', () => dispatcher.queued(packet.to));
        return { ok: true };
      }
      case 'duplicate':
        return { ok: true };
      case 'unknown_peer': // unregistered since it was read
        throw notPermitted();
      case 'recipient_inbox_full':
        throw full(kind === 'stranger' ? 'stranger allowance is full' : undefined);
      case 'network_slots_full':
        throw full('stranger allowance share of this client network is full');
      case 'sender_share_full':
        throw full("sender's share of the recipient queue is full");
      case 'registration_network_full':
        throw new RelayError('rate_limited', "the recipient's registration network is over its storage budget", BUSY_RETRY_SECONDS);
      case 'relay_busy':
        throw relayBusy();
    }
  });
}
