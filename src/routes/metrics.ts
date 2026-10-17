import type { FastifyInstance } from 'fastify';
import type { SseRegistry } from '../sse/registry.js';
import type { StorageMonitor } from '../store/capacity.js';

interface MetricsDeps {
  sseRegistry: Pick<SseRegistry, 'getStats'>;
  /** Source of the used-bytes gauge (what STORAGE_HIGH_WATER_BYTES compares). */
  storage: Pick<StorageMonitor, 'usedBytes'>;
}

/** Operator metrics (internal port), Prometheus text: open listen streams and the store's used memory. */
export async function metricsRoutes(app: FastifyInstance, deps: MetricsDeps): Promise<void> {
  app.get('/metrics', async (_req, reply) => {
    const gauge = (name: string, help: string, value: number) => `# HELP ${name} ${help}\n# TYPE ${name} gauge\n${name} ${value}\n`;
    reply.header('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
    return gauge('ace_relay_sse_connections', 'Current listen streams.', deps.sseRegistry.getStats().connections)
      + gauge('ace_relay_storage_used_bytes', 'Used memory of the store (all relay data), compared with the high-water mark.', await deps.storage.usedBytes());
  });
}
