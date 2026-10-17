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

async function shutdown(): Promise<void> {
  app.log.info('Shutting down gracefully...');
  sseRegistry.drain();
  await new Promise((r) => setTimeout(r, config.drainMs));
  await app.close();
  await metricsApp.close();
  redis.disconnect();
  subscriberRedis.disconnect();
  process.exit(0);
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

start();
