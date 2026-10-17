import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { MAX_INBOX_PAGE } from '@ace-protocol/sdk';
import type { MessageStore } from '../store/messages.js';
import type { WakeStore } from '../store/wake.js';
import { authenticate, type RouteDeps } from './shared.js';

interface InboxDeps extends RouteDeps {
  messageStore: MessageStore;
  /** Present when the relay offers wake hints: fetching re-arms them (07 § Wake hints). */
  wakes?: WakeStore;
}

const STREAM_ID_PATTERN = '^[0-9]{1,20}-[0-9]{1,20}$';
/** `since`: a stream ID, or '-' (also the meaning of an absent `since`). */
export const SINCE_PATTERN = '^(-|[0-9]{1,20}-[0-9]{1,20})$';

const inboxSchema = {
  querystring: {
    type: 'object',
    properties: {
      since: { type: 'string', pattern: SINCE_PATTERN },
      limit: { type: 'integer', minimum: 1, maximum: MAX_INBOX_PAGE },
    },
  },
} as const;

const ackSchema = {
  querystring: { type: 'object', required: ['through'], properties: { through: { type: 'string', pattern: STREAM_ID_PATTERN } } },
} as const;

/** 07 § Inbox: reading never deletes; `POST /v1/inbox/ack` does. */
export async function inboxRoutes(app: FastifyInstance, deps: InboxDeps): Promise<void> {
  const { messageStore, wakes } = deps;

  app.get('/v1/inbox', { schema: inboxSchema }, async (req: FastifyRequest, reply: FastifyReply) => {
    const query = req.query as { since?: string; limit?: number };
    const since = query.since ?? '-';
    const limit = query.limit ?? MAX_INBOX_PAGE;
    const { identity } = await authenticate(deps, req, { action: 'inbox', since, limit });
    await wakes?.rearm(identity.aceId);
    const page = await messageStore.getMessages(identity.aceId, since, limit);
    // Stored packets are already JSON: spliced in as is, never parsed and re-serialized.
    const messages = page.messages.map((m) => `{"streamId":${JSON.stringify(m.streamId)},"packet":${m.json}}`).join(',');
    return reply.type('application/json').send(`{"messages":[${messages}],"cursor":${JSON.stringify(page.cursor)}}`);
  });

  app.post('/v1/inbox/ack', { schema: ackSchema }, async (req: FastifyRequest) => {
    const { through } = req.query as { through: string };
    const { identity } = await authenticate(deps, req, { action: 'inbox-ack', through });
    await Promise.all([messageStore.ack(identity.aceId, through), wakes?.rearm(identity.aceId)]);
    return { ok: true };
  });
}
