// One capacity budget over all relay data (identities, KELs, descriptors, horizons and queues): growth stops at
// STORAGE_HIGH_WATER_BYTES of the store's used memory, freeing paths always run, /health reports the degradation.
// Owns the whole CAPACITY_REDIS_ORIGIN instance (it changes maxmemory), so it never disturbs the other suites.
import Redis from 'ioredis';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { MAX_PACKET_BYTES } from '@ace-protocol/sdk';
import { BLOCK_BYTES } from '../src/store/blocks.js';
import { FULL_STORE_RESERVE_BYTES } from '../src/store/lua.js';
import {
  CAPACITY_REDIS_ORIGIN, REDIS_URL, ack, authHeaders, block, createTestRelay, inbox, newAgent, now, packet, permit, publish, published,
  register, registered, send, type Agent, type TestRelay,
} from './helpers.js';

const origin = { origin: CAPACITY_REDIS_ORIGIN };
let admin: Redis;
beforeAll(async () => { admin = new Redis(REDIS_URL(0, CAPACITY_REDIS_ORIGIN)); });
beforeEach(async () => {
  await admin.config('SET', 'maxmemory', '0');
  await admin.flushall();
});
afterAll(async () => {
  await admin.config('SET', 'maxmemory', '0');
  await admin.flushall();
  await admin.quit();
});

const usedMemory = async () => Number(/used_memory:(\d+)/.exec(await admin.info('memory'))![1]);

/**
 * A recipient with one queued packet and one block record, a sender holding its permit, and a second registered
 * identity without a descriptor.
 */
async function seed(r: TestRelay): Promise<{ to: Agent; from: Agent; bare: Agent }> {
  const to = await published(r, { visibility: 'public' }), from = await newAgent(), bare = await registered(r);
  expect((await send(r, await packet(from, to), await permit(to, from))).statusCode).toBe(200);
  expect((await block(r, to, (await newAgent()).aceId, true, 1)).statusCode).toBe(200);
  expect((await block(r, to, from.aceId, true, 1)).statusCode).toBe(200);
  return { to, from, bare };
}

/** Freeing paths: inbox read, ack, unblocking an existing block record, unregister. */
async function expectFreeingPathsWork(r: TestRelay, to: Agent, from: Agent): Promise<void> {
  const page = await inbox(r, to);
  expect(page.statusCode).toBe(200);
  expect(page.json().messages).toHaveLength(1);
  expect((await ack(r, to, page.json().cursor)).statusCode).toBe(200);
  expect((await block(r, to, from.aceId, false, 2)).statusCode).toBe(200);
  const un = await r.app.inject({ method: 'POST', url: '/v1/unregister', headers: await authHeaders(to, { action: 'unregister' }, now() + 1) });
  expect(un.statusCode).toBe(200);
}

/**
 * Growth paths: registration, descriptor publication, send, a new block record, and (`listen`) a non-draining
 * authenticated request whose nonce is a new key. Each answers 429 rate_limited with Retry-After.
 */
async function expectGrowthRefused(r: TestRelay, to: Agent, bare: Agent, o: { listen: boolean }): Promise<void> {
  const sender = await newAgent();
  const refusals = [
    await register(r, await newAgent()),
    await publish(r, bare),
    await send(r, await packet(sender, to), await permit(to, sender)),
    await block(r, to, (await newAgent()).aceId, true, 1),
  ];
  if (o.listen) refusals.push(await r.app.inject({ method: 'GET', url: '/v1/listen', headers: await authHeaders(to, { action: 'listen', since: '-' }) }));
  for (const res of refusals) {
    expect(res.statusCode).toBe(429);
    expect(res.json().error).toBe('rate_limited');
    expect(res.headers['retry-after']).toMatch(/^\d+$/);
  }
}

describe('relay-wide capacity', () => {
  it('refuses registration, publication and send at the high-water mark; freeing paths still run; /health is 503', async () => {
    const roomy = await createTestRelay(0, {}, origin);
    // A replica of the same store whose high-water mark the store is already over.
    const full = await createTestRelay(0, { storageHighWaterBytes: MAX_PACKET_BYTES }, { ...origin, flush: false });
    try {
      const { to, from, bare } = await seed(roomy);
      await admin.set('test:other-data', 'x'.repeat(2 * MAX_PACKET_BYTES)); // identities, horizons or another tenant
      expect(await usedMemory()).toBeGreaterThan(MAX_PACKET_BYTES);

      expect((await roomy.app.inject({ method: 'GET', url: '/health' })).statusCode).toBe(200);
      const health = await full.app.inject({ method: 'GET', url: '/health' });
      expect([health.statusCode, health.json()]).toEqual([503, { ok: false, error: 'storage_high_water' }]);

      await expectGrowthRefused(full, to, bare, { listen: false });
      expect(await roomy.redis.xlen(`ace:inbox:${to.aceId}`)).toBe(1);
      await expectFreeingPathsWork(full, to, from);
    } finally {
      await full.close();
      await roomy.close();
    }
  }, 60_000);

  // Reproduction: registrations filled the store to maxmemory (noeviction) while no packets were queued; an ack then
  // failed with 500 and /health stayed 200.
  it('when the store itself is out of memory, acks and unregister succeed, growth is 429 (never 500) and /health is 503', async () => {
    const r = await createTestRelay(0, {}, origin);
    try {
      const { to, from, bare } = await seed(r);
      await admin.config('SET', 'maxmemory-policy', 'noeviction');
      // Out of memory, within the reserve the draining requests' nonces and rate counters may use.
      await admin.config('SET', 'maxmemory', String((await usedMemory()) - 64 * 1024));
      await expect(admin.set('test:probe', '1')).rejects.toThrow(/^OOM/);

      const health = await r.app.inject({ method: 'GET', url: '/health' });
      expect([health.statusCode, health.json()]).toEqual([503, { ok: false, error: 'storage_refusing_writes' }]);
      await expectGrowthRefused(r, to, bare, { listen: true });
      await expectFreeingPathsWork(r, to, from);
    } finally {
      await admin.config('SET', 'maxmemory', '0');
      await r.close();
    }
  }, 60_000);

  it('past maxmemory plus the reserve, even draining requests are refused with 429 (the reserve is a hard ceiling)', async () => {
    const r = await createTestRelay(0, {}, origin);
    try {
      const { to } = await seed(r);
      // A fresh instance can use less than the reserve twice over: pad it so maxmemory stays positive.
      await admin.set('pad', 'x'.repeat(4 * FULL_STORE_RESERVE_BYTES));
      await admin.config('SET', 'maxmemory-policy', 'noeviction');
      await admin.config('SET', 'maxmemory', String((await usedMemory()) - 2 * FULL_STORE_RESERVE_BYTES));
      const res = await inbox(r, to);
      expect([res.statusCode, res.json().error]).toEqual([429, 'rate_limited']);
      expect((await r.app.inject({ method: 'GET', url: '/health' })).statusCode).toBe(503);
    } finally {
      await admin.config('SET', 'maxmemory', '0');
      await r.close();
    }
  }, 60_000);

  it('charges each new block record to the owner\'s registration network and releases it at unregister', async () => {
    const r = await createTestRelay(0, {}, origin);
    try {
      const owner = await registered(r), peer = await newAgent();
      const net = 'n:127.0.0.0/24'; // inject's default remote address
      const before = await r.messageStore.registrationNetworkBytes(net);
      expect((await block(r, owner, peer.aceId, true, 1)).statusCode).toBe(200);
      expect((await block(r, owner, peer.aceId, false, 2)).statusCode).toBe(200); // an update: no new charge
      expect(await r.messageStore.registrationNetworkBytes(net)).toBe(before + BLOCK_BYTES);
      const un = await r.app.inject({ method: 'POST', url: '/v1/unregister', headers: await authHeaders(owner, { action: 'unregister' }, now() + 1) });
      expect(un.statusCode).toBe(200);
      // The KEL moves to the packet window, the horizon is charged for good, the block record is released.
      const after = await r.messageStore.registrationNetworkBytes(net);
      expect(after).toBeLessThan(before + BLOCK_BYTES + 512);
      expect(await r.redis.hget(`ace:identity:${owner.aceId}`, 'bb')).toBeNull();
    } finally {
      await r.close();
    }
  }, 60_000);
});
