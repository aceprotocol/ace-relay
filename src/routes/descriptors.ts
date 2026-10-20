import type { FastifyInstance, FastifyRequest } from 'fastify';
import {
  DEFAULT_PAGE_LIMIT, MAX_INBOX_PAGE, MAX_PUBLISHED_AGENT_BYTES, documentDigest, isACEId, isHandle, verifyCardBundle, verifyPublishedAgent,
} from '@ace-protocol/sdk';
import type { DescriptorStore } from '../store/descriptors.js';
import type { CardStore } from '../store/cards.js';
import type { BlockStore } from '../store/blocks.js';
import { RelayError, sdk, storageRefusal } from '../errors.js';
import { authenticate, clientOf, enforceRate, enforceRegistrationRate, networkOf, type RouteDeps } from './shared.js';

interface DescriptorDeps extends RouteDeps {
  descriptors: DescriptorStore;
  cards: CardStore;
  blocks: BlockStore;
}

const directorySchema = {
  querystring: {
    type: 'object',
    additionalProperties: false,
    properties: {
      profile: { type: 'string', maxLength: 256 },
      cursor: { type: 'string', maxLength: 512 },
      limit: { type: 'integer', minimum: 1, maximum: MAX_INBOX_PAGE },
    },
  },
} as const;

const blockSchema = {
  body: {
    type: 'object',
    additionalProperties: false,
    required: ['peer', 'blocked', 'revision'],
    properties: { peer: { type: 'string' }, blocked: { type: 'boolean' }, revision: { type: 'integer', minimum: 0, maximum: Number.MAX_SAFE_INTEGER } },
  },
} as const;

/** 07 § Descriptors and cards, and § Blocks. */
export async function descriptorRoutes(app: FastifyInstance, deps: DescriptorDeps): Promise<void> {
  const { descriptors, cards, blocks, rateLimiter, config, clock } = deps;
  const audience = config.publicRelayUrl;
  const verifyOpts = { allowLoopbackRelays: audience.startsWith('http://') };
  // Handles are written @name@host and resolve at https://host, so a relay whose public URL has a path binds none (04 § Card record).
  const bindsHandles = new URL(audience).pathname === '/';

  app.post('/v1/descriptor', { bodyLimit: MAX_PUBLISHED_AGENT_BYTES }, async (req: FastifyRequest) => {
    await enforceRegistrationRate(deps, req, 'descriptor');
    const { agent, state } = sdk(() => verifyPublishedAgent(req.body, clock(), verifyOpts));
    const d = agent.descriptor;
    if (!d.relays.includes(audience)) throw new RelayError('invalid_argument', `descriptor relays must include ${audience}`);
    // The store checks the registration and its KEL.
    const status = await descriptors.publish(agent, state.lastHash, documentDigest(d));
    if (status === 'rate_limited' || status === 'relay_busy') throw storageRefusal(status);
    if (status !== 'published') throw new RelayError(status);
    return { ok: true };
  });

  app.get('/v1/descriptor/:aceId', async (req: FastifyRequest) => {
    const { aceId } = req.params as { aceId: string };
    if (!isACEId(aceId)) throw new RelayError('unknown_peer');
    const agent = await descriptors.get(aceId, clock());
    if (!agent) throw new RelayError('unknown_peer');
    return agent;
  });

  // Self-authenticated by the record's signature; the store checks the registration, its KEL and the handle rules.
  app.post('/v1/card', { bodyLimit: MAX_PUBLISHED_AGENT_BYTES }, async (req: FastifyRequest) => {
    await enforceRegistrationRate(deps, req, 'card');
    const { record, kelState, bundle } = sdk(() => verifyCardBundle(req.body, clock(), verifyOpts));
    const { status, retryAfter } = await cards.publish({
      bundle, lastHash: kelState.lastHash, digest: documentDigest(record), atHome: record.home === audience, bindsHandles,
      network: networkOf(req),
    });
    switch (status) {
      case 'published':
        return { ok: true };
      case 'handle_mismatch':
        throw new RelayError('invalid_argument', 'a card record naming this relay as home must carry the handle bound to the identity');
      case 'claim_limited':
        throw new RelayError('rate_limited', 'this client network has claimed its handles for the day', retryAfter);
      case 'rate_limited':
      case 'relay_busy':
        throw storageRefusal(status);
      default:
        throw new RelayError(status);
    }
  });

  app.get('/v1/card/:aceId', async (req: FastifyRequest) => {
    const { aceId } = req.params as { aceId: string };
    const bundle = isACEId(aceId) ? await cards.get(aceId) : null;
    if (!bundle) throw new RelayError('unknown_peer');
    return bundle;
  });

  app.get('/v1/handles/:handle', async (req: FastifyRequest) => {
    const { handle } = req.params as { handle: string };
    const bundle = bindsHandles && isHandle(handle) ? await cards.resolveHandle(handle, audience) : null;
    if (!bundle) throw new RelayError('unknown_peer');
    return bundle;
  });

  app.get('/v1/descriptors', { schema: directorySchema }, async (req: FastifyRequest) => {
    await enforceRate(rateLimiter, `directory:${clientOf(req)}`, config.discoverRateLimit, 60, 'network');
    const q = req.query as { profile?: string; cursor?: string; limit?: number };
    if (q.cursor !== undefined && !isACEId(q.cursor)) throw new RelayError('invalid_argument', 'invalid cursor');
    return descriptors.discover(q.cursor, q.limit ?? DEFAULT_PAGE_LIMIT, q.profile, clock());
  });

  app.post('/v1/blocks', { schema: blockSchema }, async (req: FastifyRequest) => {
    const { peer, blocked, revision } = req.body as { peer: string; blocked: boolean; revision: number };
    if (!isACEId(peer)) throw new RelayError('invalid_argument', 'peer must be an ACE ID');
    const { identity } = await authenticate(deps, req, { action: 'block', peer, blocked, revision });
    if (peer === identity.aceId) throw new RelayError('invalid_argument', 'cannot block yourself');
    const status = await blocks.set(identity.aceId, peer, blocked, revision, identity.lastHash);
    if (status === 'rate_limited' || status === 'relay_busy') throw storageRefusal(status);
    if (status !== 'ok') throw new RelayError(status);
    return { ok: true };
  });
}
