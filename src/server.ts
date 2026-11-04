import Fastify from 'fastify';
import { loadConfig } from './config.js';
import { createRedisClient } from './store/redis.js';
import { buildApp } from './app.js';
import { metricsRoutes } from './routes/metrics.js';

// Fails startup on a malformed value or without PUBLIC_RELAY_URL.
const config = loadConfig();

const redis = createRedisClient(config.redisUrl);
const subscriberRedis = createRedisClient(config.redisUrl); // separate connection for SUBSCRIBE

const { app, sseRegistry, storageMonitor } = await buildApp({
  config,
  redis,
  subscriberRedis,
  logger: process.env.NODE_ENV !== 'production' ? { transport: { target: 'pino-pretty' } } : true,
});

// Metrics on a separate, internal port.
const metricsApp = Fastify({ logger: false });
await metricsApp.register(async (instance) => metricsRoutes(instance, { sseRegistry, storage: storageMonitor }));

async function start(): Promise<void> {
  try {
    await app.listen({ host: '0.0.0.0', port: config.port });
    await metricsApp.listen({ host: '0.0.0.0', port: config.metricsPort });
    app.log.info(`Metrics server listening on :${config.metricsPort}`);
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
}

/**
 * Ends the listen streams (they reconnect elsewhere) and refuses new ones, lets in-flight requests finish for DRAIN_MS,
 * then closes. Runs once, whichever signal comes first or again.
 */
let stopping = false;
async function shutdown(signal: string): Promise<void> {
  if (stopping) return;
  stopping = true;
  app.log.info({ signal }, 'shutting down');
  try {
    sseRegistry.drain();
    await new Promise((r) => setTimeout(r, config.drainMs));
    await app.close();
    await metricsApp.close();
  } catch (err) {
    app.log.error({ err }, 'shutdown failed');
    process.exit(1);
  }
  redis.disconnect();
  subscriberRedis.disconnect();
  process.exit(0);
}

process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));

start();
