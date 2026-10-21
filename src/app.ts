import Fastify, { type FastifyInstance, type FastifyServerOptions } from 'fastify';
import type Redis from 'ioredis';
import { BODY_LIMIT_BYTES, type RelayConfig } from './config.js';
import { applyHttpHardening } from './http/hardening.js';
import { IdentityStore } from './store/identity.js';
import { MessageStore } from './store/messages.js';
import { DescriptorStore } from './store/descriptors.js';
import { CardStore } from './store/cards.js';
import { BlockStore } from './store/blocks.js';
import { RateLimiter } from './store/rate-limit.js';
import { ReplayStore } from './store/replay.js';
import { StorageMonitor } from './store/capacity.js';
import { WakeStore } from './store/wake.js';
import { WakeDispatcher } from './wake/dispatcher.js';
import { SseRegistry } from './sse/registry.js';
import { healthRoutes } from './routes/health.js';
import { registerRoutes } from './routes/register.js';
import { descriptorRoutes } from './routes/descriptors.js';
import { sendRoutes } from './routes/send.js';
import { listenRoutes } from './routes/listen.js';
import { inboxRoutes } from './routes/inbox.js';
import { wakeRoutes } from './routes/wake.js';
import { checkIpRate } from './routes/shared.js';

export interface RelayApp {
  app: FastifyInstance;
  identityStore: IdentityStore;
  messageStore: MessageStore;
  descriptorStore: DescriptorStore;
  cardStore: CardStore;
  blockStore: BlockStore;
  sseRegistry: SseRegistry;
  storageMonitor: StorageMonitor;
  wakeStore: WakeStore;
  wakeDispatcher: WakeDispatcher;
}

export interface BuildAppOptions {
  config: RelayConfig;
  redis: Redis;
  /** A separate connection: it enters SUBSCRIBE mode. */
  subscriberRedis: Redis;
  logger?: FastifyServerOptions['logger'];
  /** The protocol clock in Unix seconds (default the system clock). */
  clock?: () => number;
  /** The wake requests' fetch (default: public HTTPS, pinned, no redirects). */
  wakeFetch?: typeof fetch;
}

/** The ACE relay (ace-spec 07-relay.md). The caller listens and shuts down. */
export async function buildApp(opts: BuildAppOptions): Promise<RelayApp> {
  const { config, redis, subscriberRedis } = opts;
  const clock = opts.clock ?? (() => Math.floor(Date.now() / 1000));

  const app = Fastify({
    ajv: { customOptions: { removeAdditional: false } },
    trustProxy: config.trustProxy,
    logger: opts.logger ?? false,
    bodyLimit: BODY_LIMIT_BYTES,
  });
  // A body-less POST (e.g. /v1/unregister) may still carry Content-Type: application/json.
  const jsonParser = app.getDefaultJsonParser('error', 'error');
  app.removeContentTypeParser('application/json');
  app.addContentTypeParser('application/json', { parseAs: 'string' }, (req, body, done) => {
    const text = typeof body === 'string' ? body : body.toString('utf8');
    if (text === '') return done(null, undefined);
    return jsonParser(req, text, done);
  });
  applyHttpHardening(app);

  const messageStore = new MessageStore(redis, config);
  const identityStore = new IdentityStore(redis, messageStore.budget);
  const descriptorStore = new DescriptorStore(redis, messageStore.budget);
  const cardStore = new CardStore(redis, messageStore.budget, config.handleClaimsPerNetworkPerDay, config.publicRelayUrl);
  const blockStore = new BlockStore(redis, messageStore.budget);
  const rateLimiter = new RateLimiter(redis, config.storageHighWaterBytes);
  const replayStore = new ReplayStore(redis);
  const storageMonitor = new StorageMonitor(redis, config.storageHighWaterBytes);
  const sseRegistry = new SseRegistry(redis, subscriberRedis, messageStore, identityStore, config, app.log);
  const wakeStore = new WakeStore(redis, messageStore.budget);
  const wakeDispatcher = new WakeDispatcher(wakeStore, sseRegistry, config, app.log, opts.wakeFetch);
  app.addHook('onClose', async () => wakeDispatcher.close());
  // Wake hints (07 § Wake hints): only when the operator lists gateways.
  const wake = wakeDispatcher.enabled ? { wakes: wakeStore, dispatcher: wakeDispatcher } : {};

  const deps = { identityStore, rateLimiter, replayStore, config, clock };
  // The per-network limit of every /v1 route, counted before the body is parsed or validated.
  app.addHook('onRequest', async (req) => {
    if (req.routeOptions.url?.startsWith('/v1/')) await checkIpRate(deps, req);
  });
  await app.register(async (i) => healthRoutes(i, { storage: storageMonitor }));
  await app.register(async (i) => registerRoutes(i, { ...deps, sseRegistry }));
  await app.register(async (i) => descriptorRoutes(i, { ...deps, descriptors: descriptorStore, cards: cardStore, blocks: blockStore }));
  await app.register(async (i) => sendRoutes(i, { ...deps, messageStore, blocks: blockStore, descriptors: descriptorStore, cards: cardStore, sseRegistry, ...wake }));
  await app.register(async (i) => inboxRoutes(i, { ...deps, messageStore, ...wake }));
  await app.register(async (i) => listenRoutes(i, { ...deps, sseRegistry, ...wake }));
  if (wakeDispatcher.enabled) await app.register(async (i) => wakeRoutes(i, { ...deps, wakes: wakeStore }));

  sseRegistry.startListening();
  return { app, identityStore, messageStore, descriptorStore, cardStore, blockStore, sseRegistry, storageMonitor, wakeStore, wakeDispatcher };
}
