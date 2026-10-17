import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import type { SseRegistry } from '../sse/registry.js';
import { RelayError } from '../errors.js';
import { authenticate, type RouteDeps } from './shared.js';
import { SINCE_PATTERN } from './inbox.js';

interface ListenDeps extends RouteDeps {
  sseRegistry: SseRegistry;
}

const listenSchema = {
  querystring: {
    type: 'object',
    properties: { since: { type: 'string', pattern: SINCE_PATTERN } },
  },
} as const;

/** 07 § Listen: catchup after `since`, then live messages, as SSE. Limits are per identity and global only. */
export async function listenRoutes(app: FastifyInstance, deps: ListenDeps): Promise<void> {
  const { sseRegistry } = deps;

  app.get('/v1/listen', { schema: listenSchema }, async (req: FastifyRequest, reply: FastifyReply) => {
    const since = (req.query as { since?: string }).since ?? '-';
    const { identity } = await authenticate(deps, req, { action: 'listen', since });
    const aceId = identity.aceId;

    const check = sseRegistry.canConnect(aceId);
    if (!check.ok) throw new RelayError('rate_limited', `SSE ${check.error}`, 60);

    // Hijack so Fastify does not serialize the resolved handler value and end the stream.
    reply.hijack();
    reply.raw.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no',
    });
    reply.raw.write(`event: connected\ndata: ${JSON.stringify({ aceId })}\n\n`);

    // No await between canConnect and add: the slot is reserved synchronously.
    // Resolves once the catchup backlog is written (or the connection is closed).
    await sseRegistry.add(aceId, identity.requestDigest, reply, since);
  });
}
