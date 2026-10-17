import type { FastifyInstance } from 'fastify';
import type { StorageMonitor } from '../store/capacity.js';

interface HealthDeps {
  storage: Pick<StorageMonitor, 'health'>;
}

/** 200 while the relay accepts growth; 503 when Redis is unreachable, refuses writes, or is at the high-water mark. */
export async function healthRoutes(app: FastifyInstance, deps: HealthDeps): Promise<void> {
  app.get('/health', async (_request, reply) => {
    let health;
    try {
      health = await deps.storage.health();
    } catch {
      return reply.status(503).send({ ok: false, error: 'redis_unavailable' });
    }
    if (health !== 'ok') return reply.status(503).send({ ok: false, error: health });
    return { ok: true };
  });
}
