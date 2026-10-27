// Test harness: the real relay app on a scratch Redis db, plus SDK-built requests.
//
// Redis: ACE_TEST_REDIS_ORIGIN (default redis://localhost:16379). Suites run in parallel and each owns one db
// (all below 16, the server default), flushed when the suite starts:
//
//    1 register             2 descriptors        3 send               4 inbox            5 listen
//    6 fp-minimal           7 vectors            8 e2e relay A        9 e2e relay B     10 operations
//   11 fp-minimal (limits) 12 retention         13 register (rate)   14 cards          15 send (limits)
//    0 wake
//
// The capacity suite owns a whole second instance, ACE_TEST_CAPACITY_REDIS_ORIGIN (default redis://localhost:16380):
// it changes maxmemory and fills the store.
import Redis from 'ioredis';
import { vi } from 'vitest';
import {
  MemoryStore, ProfileSet, StorePrekeyVault, SoftwareIdentity, canonicalStateBytes, createAuthHeaders, createCardRecord, createDescriptor,
  createPacket, createPermit, createRegistrationRequest, prekeyPublicKey, signingMessage, toBase64, verifyKel, type AgentCard, type CardBundle, type Contact, type DeliveryPermit, type Packet,
  type PrekeyVault, type PublishedAgent, type RelayAuthRequest,
} from '@ace-protocol/sdk';
import { buildApp, type RelayApp } from '../src/app.js';
import { parseCidrs, validateConfig, type RelayConfig } from '../src/config.js';

export const REDIS_ORIGIN = process.env.ACE_TEST_REDIS_ORIGIN ?? 'redis://localhost:16379';
export const CAPACITY_REDIS_ORIGIN = process.env.ACE_TEST_CAPACITY_REDIS_ORIGIN ?? 'redis://localhost:16380';
export const REDIS_URL = (db: number, origin = REDIS_ORIGIN) => `${origin}/${db}`;
export const RELAY_URL = 'https://relay.test';
/** Not canonical relay URLs under the ACE HTTPS host grammar (02 § Relay URL): IP literal, empty label, label edge '-', trailing '.'. */
export const BAD_RELAY_URLS = ['https://[::1]', 'https://a..b', 'https://-a.example', 'https://a-.example', 'https://example.com.'];

/** Config overrides; trusted registration networks as CIDR strings. */
export type TestOverrides = Partial<Omit<RelayConfig, 'trustedRegistrationNetworks'>> & { trustedRegistrationNetworks?: string[] };

/** Generous limits, so suites hit only the limit they test. */
export function testConfig(overrides: TestOverrides = {}): RelayConfig {
  return validateConfig({
    port: 0, metricsPort: 0, publicRelayUrl: RELAY_URL, redisUrl: '', trustProxy: false,
    ipRateLimit: 100_000, registerRateLimit: 100_000, trustedRegisterRateLimit: 100_000, discoverRateLimit: 100_000, sendRateLimit: 100_000,
    strangerIpRateLimit: 100_000, strangerRecipientRateLimit: 100_000, handleClaimsPerNetworkPerDay: 100_000,
    messageTtlSeconds: 604_800, maxInboxEntries: 10_000, maxInboxBytes: 64 * 1024 * 1024,
    maxInboxSenderBytes: 64 * 1024 * 1024, storageHighWaterBytes: 1024 * 1024 * 1024,
    registrationNetworkBytes: 1024 * 1024 * 1024, trustedRegistrationNetworkBytes: 1024 * 1024 * 1024,
    ssePerIdentity: 3, globalSseLimit: 10_000, heartbeatIntervalMs: 60_000, drainMs: 0, sseCatchupLimit: 200, sseWriteTimeoutMs: 30_000,
    wakeGateways: [], wakeMinIntervalSeconds: 30, wakeTimeoutMs: 5_000,
    ...overrides,
    trustedRegistrationNetworks: parseCidrs(overrides.trustedRegistrationNetworks ?? []),
  }, false);
}

export interface TestRelay extends RelayApp {
  redis: Redis;
  subscriberRedis: Redis;
  config: RelayConfig;
  close(): Promise<void>;
}

/**
 * Builds the full relay on db `db` of `origin` (default REDIS_ORIGIN; flushed unless `flush: false`). `clock`: the
 * relay's protocol clock in Unix seconds (default the system clock). `wakeFetch`: the wake requests' fetch.
 */
export async function createTestRelay(db: number, overrides: TestOverrides = {},
  o: { clock?: () => number; flush?: boolean; origin?: string; wakeFetch?: typeof fetch } = {}): Promise<TestRelay> {
  return startRelay(REDIS_URL(db, o.origin), testConfig(overrides), o.flush ?? true, o.clock, o.wakeFetch);
}

/** Another relay instance on db `db` (not flushed) with `relay`'s config: replicas sharing one Redis. */
export function createReplica(relay: TestRelay, db: number): Promise<TestRelay> {
  return startRelay(REDIS_URL(db), relay.config, false);
}

async function startRelay(url: string, config: RelayConfig, flush: boolean, clock?: () => number, wakeFetch?: typeof fetch): Promise<TestRelay> {
  const redis = new Redis(url);
  const subscriberRedis = new Redis(url);
  if (flush) await redis.flushdb();
  const relay = await buildApp({ config, redis, subscriberRedis, clock, wakeFetch });
  await relay.app.ready();
  return {
    ...relay, redis, subscriberRedis, config,
    async close() {
      relay.sseRegistry.drain();
      await relay.app.close();
      await Promise.all([redis.quit(), subscriberRedis.quit()]);
    },
  };
}

export const now = () => Math.floor(Date.now() / 1000);
export const text = new ProfileSet(['text']);

/** A generated identity with its own prekey vault. */
export interface Agent {
  id: SoftwareIdentity;
  aceId: string;
  vault: PrekeyVault;
}

/** `age`: seconds the log's events are back-dated (signing never precedes the log's last event, 01 rule 3). */
export async function newAgent(age = 0): Promise<Agent> {
  const id = await SoftwareIdentity.generate({ now: now() - age });
  const vault = new StorePrekeyVault(new MemoryStore());
  await vault.rotate(now());
  return { id, aceId: id.getACEId(), vault };
}

export async function register(relay: TestRelay, agent: Agent, timestamp?: number) {
  return relay.app.inject({ method: 'POST', url: '/v1/register', payload: await createRegistrationRequest(agent.id, { audience: RELAY_URL, timestamp: timestamp }) });
}

export async function unregister(relay: TestRelay, agent: Agent, timestamp = now() + 1) {
  return relay.app.inject({ method: 'POST', url: '/v1/unregister', headers: await authHeaders(agent, { action: 'unregister' }, timestamp) });
}

export async function registered(relay: TestRelay, age = 0): Promise<Agent> {
  const a = await newAgent(age);
  const res = await register(relay, a);
  if (res.statusCode !== 200) throw new Error(`register failed: ${res.body}`);
  return a;
}

export async function descriptorOf(agent: Agent, o: { relays?: string[]; now?: number; ttl?: number } = {}): Promise<PublishedAgent> {
  const pk = (await agent.vault.current())!;
  return createDescriptor(agent.id, {
    relays: o.relays ?? [RELAY_URL], prekey: { id: pk.id, publicKey: pk.publicKey }, profiles: text.descriptors(), now: o.now, ttl: o.ttl,
  });
}

/**
 * `doc` (a descriptor or card record) with its claims re-signed by `agent`'s current signing delegation under `action`
 * ('agent-descriptor' | 'card-record'), skipping the SDK's create-time checks: for documents the SDK would refuse to make.
 */
export async function resign<T extends { issuedAt: number; signature?: unknown }>(agent: Agent, action: string, doc: T): Promise<T> {
  const { signature: _, ...claims } = doc;
  const seq = verifyKel(agent.id.getKel(), now()).signing!.seq;
  const value = toBase64(await agent.id.sign(signingMessage(agent.aceId, doc.issuedAt, seq, canonicalStateBytes(claims)), action));
  return { ...claims, signature: { scheme: 'ml-dsa-65', seq, value } } as unknown as T;
}

export async function publish(relay: TestRelay, agent: Agent, o: Parameters<typeof descriptorOf>[1] = {}) {
  return relay.app.inject({ method: 'POST', url: '/v1/descriptor', payload: await descriptorOf(agent, o) });
}

/** Card record options; `home` defaults to RELAY_URL, `contact` to closed, `listed` to false. */
export interface CardOptions { home?: string; handle?: string; contact?: Contact; listed?: boolean; card?: AgentCard; pay?: string[]; now?: number }

export function cardOf(agent: Agent, o: CardOptions = {}): Promise<CardBundle> {
  return createCardRecord(agent.id, {
    home: o.home ?? RELAY_URL, handle: o.handle, contact: o.contact ?? 'closed', listed: o.listed ?? false, card: o.card, pay: o.pay, now: o.now,
  });
}

export async function publishCard(relay: TestRelay, agent: Agent, o: CardOptions = {}, remoteAddress?: string) {
  return postCard(relay, await cardOf(agent, o), remoteAddress);
}

export function postCard(relay: TestRelay, bundle: unknown, remoteAddress?: string) {
  return relay.app.inject({ method: 'POST', url: '/v1/card', payload: bundle as object, ...(remoteAddress ? { remoteAddress } : {}) });
}

/** Registered and published; with any card option (contact, listed, handle) also a card record. */
export async function published(relay: TestRelay, o: Parameters<typeof descriptorOf>[1] & Pick<CardOptions, 'contact' | 'listed' | 'handle'> = {}): Promise<Agent> {
  const a = await registered(relay);
  const res = await publish(relay, a, o);
  if (res.statusCode !== 200) throw new Error(`publish failed: ${res.body}`);
  if (o.contact !== undefined || o.listed !== undefined || o.handle !== undefined) {
    const c = await publishCard(relay, a, { contact: o.contact, listed: o.listed, handle: o.handle, now: o.now });
    if (c.statusCode !== 200) throw new Error(`card failed: ${c.body}`);
  }
  return a;
}

/** Lower-case auth headers for this relay's audience. */
export async function authHeaders(agent: Agent, req: RelayAuthRequest, timestamp = now(), audience = RELAY_URL): Promise<Record<string, string>> {
  const h = await createAuthHeaders(agent.id, req, timestamp, { audience });
  return Object.fromEntries(Object.entries(h).map(([k, v]) => [k.toLowerCase(), v]));
}

/** A peer prekey for private content: the Base64 X-Wing public key of a random seed (04 § Peer prekeys). */
export const somePrekey = (): string => toBase64(prekeyPublicKey(crypto.getRandomValues(new Uint8Array(32))));

export async function packet(from: Agent, to: Agent, o: { message?: string; timestamp?: number; messageId?: string } = {}): Promise<Packet> {
  const pk = (await to.vault.current())!;
  return createPacket({
    identity: from.id, to: to.aceId, prekey: { id: pk.id, publicKey: pk.publicKey }, timestamp: o.timestamp, messageId: o.messageId,
    content: { type: 'ace:text:1', schemaDigest: text.digestOf('ace:text:1')!, body: { message: o.message ?? 'hello' }, prekey: somePrekey() },
  });
}

export function permit(issuer: Agent, subject: Agent, o: { now?: number; ttl?: number } = {}): Promise<DeliveryPermit> {
  return createPermit(issuer.id, subject.aceId, o);
}

export function send(relay: TestRelay, p: unknown, permitValue?: unknown, remoteAddress?: string) {
  return relay.app.inject({
    method: 'POST', url: '/v1/send', payload: { packet: p, ...(permitValue !== undefined ? { permit: permitValue } : {}) },
    ...(remoteAddress ? { remoteAddress } : {}),
  });
}

export async function inbox(relay: TestRelay, agent: Agent, since = '-', limit = 100) {
  const qs = new URLSearchParams({ ...(since === '-' ? {} : { since }), limit: String(limit) });
  return relay.app.inject({ method: 'GET', url: `/v1/inbox?${qs}`, headers: await authHeaders(agent, { action: 'inbox', since, limit }) });
}

export async function ack(relay: TestRelay, agent: Agent, through: string) {
  return relay.app.inject({ method: 'POST', url: `/v1/inbox/ack?through=${through}`, headers: await authHeaders(agent, { action: 'inbox-ack', through }) });
}

export async function block(relay: TestRelay, owner: Agent, peer: string, blocked: boolean, revision: number) {
  return relay.app.inject({
    method: 'POST', url: '/v1/blocks', payload: { peer, blocked, revision },
    headers: await authHeaders(owner, { action: 'block', peer, blocked, revision }),
  });
}

export async function putWake(relay: TestRelay, agent: Agent, gateway: string, token: string) {
  return relay.app.inject({
    method: 'PUT', url: '/v1/wake', payload: { gateway, token }, headers: await authHeaders(agent, { action: 'wake', gateway, token }),
  });
}

export async function deleteWake(relay: TestRelay, agent: Agent) {
  return relay.app.inject({ method: 'DELETE', url: '/v1/wake', headers: await authHeaders(agent, { action: 'wake' }) });
}

/** The stored wake registration of `aceId`, or null. */
export async function wakeOf(relay: TestRelay, aceId: string): Promise<{ gateway: string; token: string; armed: boolean } | null> {
  const h = await relay.redis.hgetall(`ace:wake:${aceId}`);
  return h.g === undefined ? null : { gateway: h.g, token: h.t, armed: h.a === '1' };
}

/** Ends each listen response once its catchup is written, so `inject` resolves with a finite body. */
export function endListenAfterCatchup(relay: TestRelay) {
  const original = relay.sseRegistry.add.bind(relay.sseRegistry);
  return vi.spyOn(relay.sseRegistry, 'add').mockImplementation(async (aceId, requestDigest, reply, cursor) => {
    await original(aceId, requestDigest, reply, cursor);
    reply.raw.end();
  });
}

/** The events of a relay listen stream (the relay writes `\n` line endings only); ends with the stream. */
export async function* sseEvents(body: ReadableStream<Uint8Array>): AsyncGenerator<{ id?: string; event?: string; data: string }, void, undefined> {
  const decoder = new TextDecoder();
  let buf = '';
  try {
    for await (const chunk of body) {
      buf += decoder.decode(chunk, { stream: true });
      for (let end = buf.indexOf('\n\n'); end >= 0; end = buf.indexOf('\n\n')) {
        const fields = buf.slice(0, end).split('\n').filter((l) => !l.startsWith(':')).map((l) => [l.slice(0, l.indexOf(':')), l.slice(l.indexOf(':') + 2)]);
        buf = buf.slice(end + 2);
        const ev = Object.fromEntries(fields) as { id?: string; event?: string; data?: string };
        if (ev.data !== undefined) yield { ...ev, data: ev.data };
      }
    }
  } catch (e) {
    if ((e as Error).name !== 'AbortError') throw e;
  }
}
