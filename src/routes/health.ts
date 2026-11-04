import type { FastifyInstance } from 'fastify';
import type { StorageMonitor } from '../store/capacity.js';

interface HealthDeps {
  storage: Pick<StorageMonitor, 'health'>;
}

/** /health is public and unthrottled: at most one store probe per interval, shared by every request in it. */
const PROBE_INTERVAL_MS = 1000;

/** 200 while the relay accepts growth; 503 when Redis is unreachable, refuses writes, or is at the high-water mark. */
export async function healthRoutes(app: FastifyInstance, deps: HealthDeps): Promise<void> {
  let probe: { at: number; result: Promise<string> } | undefined;
  app.get('/health', async (_request, reply) => {
    const now = Date.now();
    if (probe === undefined || now - probe.at >= PROBE_INTERVAL_MS) {
      probe = { at: now, result: deps.storage.health().catch(() => 'redis_unavailable') };
    }
    const health = await probe.result;
    if (health !== 'ok') return reply.status(503).send({ ok: false, error: health });
    return { ok: true };
  });
}
