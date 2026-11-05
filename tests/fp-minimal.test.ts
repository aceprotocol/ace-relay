// Stranger quotas, storage bounds, liveness of permit issuers, unknown routes.
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  MAX_PACKET_BYTES, OFFLINE_WINDOW_SECONDS, SoftwareIdentity, SoftwareKey, createPermit, createRegistrationRequest, fromBase64, generateSoftwareKey, keyDigest,
  toBase64, verifyKel, type KelEvent,
} from '@ace-protocol/sdk';
import { createDelegation, createInception, createRotation } from '@ace-protocol/sdk/testing';
import {
  networkBytes,
  RELAY_URL, authHeaders, block, createTestRelay, descriptorOf, newAgent, now, packet, publish, publishCard, published, register, send, unregister,
  type Agent, type TestRelay,
} from './helpers.js';
import { REGNET_STORED_KEY_PREFIX } from '../src/store/keyspace.js';
import { HORIZON_BYTES } from '../src/store/identity.js';

let relay: TestRelay;
beforeAll(async () => { relay = await createTestRelay(6); });
afterAll(async () => { await relay.close(); });

const registerFrom = async (r: TestRelay, agent: Agent, remoteAddress: string, timestamp?: number) =>
  r.app.inject({ method: 'POST', url: '/v1/register', payload: await createRegistrationRequest(agent.id, { audience: RELAY_URL, timestamp }), remoteAddress });

describe('A7 stranger allowance', () => {
  it('stranger network cap 2 per recipient', async () => {
    const to = await published(relay, { contact: 'open' });
    expect((await send(relay, await packet(await newAgent(), to), undefined, '203.0.113.1')).statusCode).toBe(200);
    expect((await send(relay, await packet(await newAgent(), to), undefined, '203.0.113.2')).statusCode).toBe(200);
    const full = await send(relay, await packet(await newAgent(), to), undefined, '203.0.113.3');
    expect(full.statusCode).toBe(429);
    expect(full.json().error).toBe('recipient_inbox_full');
    expect(full.headers['retry-after']).toMatch(/^[0-9]+$/);
    // Another client network has its own share.
    expect((await send(relay, await packet(await newAgent(), to), undefined, '198.51.100.1')).statusCode).toBe(200);
  });

  it('blocked stranger does not consume allowance', async () => {
    const r = await createTestRelay(11, { strangerIpRateLimit: 1, strangerRecipientRateLimit: 1 });
    try {
      const to = await published(r, { contact: 'open' }), blocked = await newAgent();
      expect((await block(r, to, blocked.aceId, true, 1)).statusCode).toBe(200);
      for (let i = 0; i < 3; i++) {
        expect((await send(r, await packet(blocked, to), undefined, '203.0.113.9')).json()).toEqual({ error: 'not_permitted', message: 'not permitted' });
      }
      // Neither the network's nor the recipient's stranger bucket was charged by the refused sends.
      expect((await send(r, await packet(await newAgent(), to), undefined, '203.0.113.9')).statusCode).toBe(200);
    } finally {
      await r.close();
    }
  });
});

describe('A10 storage bounds', () => {
  it('registration and descriptor bytes charged to network budget', async () => {
    const r = await createTestRelay(11, { registrationNetworkBytes: MAX_PACKET_BYTES });
    try {
      const net = 'n:203.0.113.0/24';
      const a = await newAgent();
      expect((await registerFrom(r, a, '203.0.113.7')).statusCode).toBe(200);
      const kelBytes = Buffer.byteLength(JSON.stringify(a.id.getKel()));
      expect(await networkBytes(r, net)).toBe(kelBytes);
      // The descriptor is charged to the network the identity registered from, wherever it is published from.
      expect((await publish(r, a)).statusCode).toBe(200);
      const withDescriptor = await networkBytes(r, net);
      expect(withDescriptor).toBeGreaterThan(kelBytes + 4000);
      // Fill the network's budget to within 10 bytes: the next registration and a larger descriptor are refused.
      await r.redis.incrby(REGNET_STORED_KEY_PREFIX + net, MAX_PACKET_BYTES - withDescriptor - 10);
      const b = await newAgent();
      const refused = await registerFrom(r, b, '203.0.113.8');
      expect(refused.statusCode).toBe(429);
      expect(refused.json().error).toBe('rate_limited');
      expect(refused.headers['retry-after']).toMatch(/^[0-9]+$/);
      expect((await publish(r, a, { now: now() + 1, relays: [RELAY_URL, 'https://second.test'] })).json().error).toBe('rate_limited');
      expect((await publishCard(r, a, { card: { description: 'a card' } })).json().error).toBe('rate_limited');
      // Other networks are unaffected.
      expect((await registerFrom(r, b, '198.51.100.8')).statusCode).toBe(200);
      expect((await publish(r, b)).statusCode).toBe(200);
      // Unregister releases the descriptor bytes at once; the retired KEL stays charged while it is kept, and the
      // fixed-size horizon is charged for good.
      const before = await networkBytes(r, net);
      const un = await r.app.inject({ method: 'POST', url: '/v1/unregister', headers: await authHeaders(a, { action: 'unregister' }, now() + 2) });
      expect(un.statusCode).toBe(200);
      expect(before - (await networkBytes(r, net))).toBe(withDescriptor - kelBytes - HORIZON_BYTES);
    } finally {
      await r.close();
    }
  });

  it('retired identity: KEL, descriptor and card record expire after OFFLINE_WINDOW, the anti-rollback horizon stays', async () => {
    const a = await published(relay, { contact: 'open', handle: 'retiree' });
    const t = now();
    const un = await relay.app.inject({ method: 'POST', url: '/v1/unregister', headers: await authHeaders(a, { action: 'unregister' }, t + 1) });
    expect(un.statusCode).toBe(200);
    for (const key of [`ace:identity:${a.aceId}`, `ace:descriptor:${a.aceId}`, `ace:card:${a.aceId}`]) {
      const ttl = await relay.redis.ttl(key);
      expect(ttl).toBeGreaterThan(OFFLINE_WINDOW_SECONDS - 10);
      expect(ttl).toBeLessThanOrEqual(OFFLINE_WINDOW_SECONDS);
    }
    expect(await relay.redis.ttl(`ace:horizon:${a.aceId}`)).toBe(-1);
    expect(Buffer.byteLength(JSON.stringify(await relay.redis.hgetall(`ace:horizon:${a.aceId}`)))).toBeLessThan(HORIZON_BYTES);
    // Within the window the barrier holds; a re-registration keeps the history again.
    expect((await register(relay, a, t)).json().error).toBe('identity_conflict');
    expect((await register(relay, a, t + 2)).json()).toEqual({ ok: true, status: 'registered' });
    expect(await relay.redis.ttl(`ace:identity:${a.aceId}`)).toBe(-1);
    expect(await relay.redis.ttl(`ace:descriptor:${a.aceId}`)).toBe(-1);
    expect(await relay.redis.ttl(`ace:card:${a.aceId}`)).toBe(-1);
    // After the window (the byte-heavy keys expired) the barrier and the descriptor and card horizons still hold.
    const un2 = await relay.app.inject({ method: 'POST', url: '/v1/unregister', headers: await authHeaders(a, { action: 'unregister' }, t + 3) });
    expect(un2.statusCode).toBe(200);
    await relay.redis.del(`ace:identity:${a.aceId}`, `ace:descriptor:${a.aceId}`, `ace:card:${a.aceId}`);
    expect((await register(relay, a, t + 3)).json().error).toBe('identity_conflict');
    expect((await register(relay, a, t + 4)).json()).toEqual({ ok: true, status: 'registered' });
    // Signing dates a document no earlier than the log's last event, so these may land on the horizon's issuedAt: they
    // differ in claims (ttl, contact) and are stale either way.
    expect((await publish(relay, a, { now: t - 60, ttl: 3600 })).json().error).toBe('stale_descriptor');
    expect((await publish(relay, a, { now: t + 4 })).statusCode).toBe(200);
    expect((await publishCard(relay, a, { handle: 'retiree', contact: 'closed', now: t - 60 })).json().error).toBe('stale_descriptor');
    // The handle binding outlived it all.
    expect((await publishCard(relay, a, { now: t + 4 })).json().error).toBe('invalid_argument');
    expect((await publishCard(relay, a, { handle: 'retiree', now: t + 4 })).statusCode).toBe(200);
  });

  // The rollback cases run on a fixed protocol clock: every KEL event and request is dated from T, never the system clock.
  const T = 1_760_140_800;
  let fixed: TestRelay;
  beforeAll(async () => { fixed = await createTestRelay(6, {}, { clock: () => T + 10, flush: false }); });
  afterAll(async () => { await fixed.close(); });
  const expire = (aceId: string) => fixed.redis.del(`ace:identity:${aceId}`, `ace:descriptor:${aceId}`);
  const unregistered = async (a: Agent, at: number) => expect((await unregister(fixed, a, at)).statusCode).toBe(200);

  it('rollback after expiry refused', async () => {
    // A superseded delegation key (same root epoch) and a superseded root (an older epoch).
    const a = await newAgent(0, T);
    expect((await register(fixed, a, T)).statusCode).toBe(200);
    const oldDelegation = SoftwareIdentity.fromExport(a.id.exportPrivateKey());
    await a.id.delegate({ now: T });
    const oldRoot = SoftwareIdentity.fromExport(a.id.exportPrivateKey());
    await a.id.rotate({ now: T });
    expect((await register(fixed, a, T + 1)).json()).toEqual({ ok: true, status: 'rotated' });
    await unregistered(a, T + 2);
    await expire(a.aceId);
    const old = (id: SoftwareIdentity) => ({ ...a, id });
    expect((await register(fixed, old(oldRoot), T + 3)).json().error).toBe('kel_conflict');
    expect((await register(fixed, old(oldDelegation), T + 3)).json().error).toBe('kel_conflict');
    // In the same epoch: a strict prefix of the retained epoch is stale_seq, a dlg fork kel_conflict.
    const b = await newAgent(0, T);
    expect((await register(fixed, b, T)).statusCode).toBe(200);
    const bOld = SoftwareIdentity.fromExport(b.id.exportPrivateKey());
    await b.id.delegate({ now: T });
    expect((await register(fixed, b, T + 1)).json()).toEqual({ ok: true, status: 'rotated' });
    await unregistered(b, T + 2);
    await expire(b.aceId);
    expect((await register(fixed, { ...b, id: bOld }, T + 3)).json().error).toBe('stale_seq');
    await bOld.delegate({ now: T });
    expect((await register(fixed, { ...b, id: bOld }, T + 3)).json().error).toBe('kel_conflict');
  });

  it('a forked dlg-only candidate after epochSeq is refused', async () => {
    const a = await newAgent(0, T);
    const fork = SoftwareIdentity.fromExport(a.id.exportPrivateKey());
    await a.id.delegate({ now: T });
    expect((await register(fixed, a, T)).statusCode).toBe(200);
    await unregistered(a, T + 1);
    await expire(a.aceId);
    // Same epoch start, then delegations the retired log never had: longer than it, no rot.
    await fork.delegate({ now: T });
    await fork.delegate({ now: T });
    expect(fork.getKel()).toHaveLength(a.id.getKel().length + 1);
    expect((await register(fixed, { ...a, id: fork }, T + 2)).json().error).toBe('kel_conflict');
  });

  it('the horizon keeps the reclaim point: the next root reclaims after the KEL expired (01 rule 6)', async () => {
    const [r0, r1, r2, b0, b1] = Array.from({ length: 5 }, () => generateSoftwareKey());
    const d = (k: SoftwareKey) => keyDigest(k.scheme, k.publicKey());
    // An identity whose software root is held in the export, its signing key the last dlg's.
    const as = (root: SoftwareKey, signing: SoftwareKey, kel: KelEvent[]): Agent => {
      const id = SoftwareIdentity.fromExport({ rootSeed: toBase64(root.seed), signingSeed: toBase64(signing.seed), kel });
      return { id, aceId: id.getACEId(), vault: undefined as never };
    };
    const extend = async (kel: KelEvent[], ev: KelEvent, root: SoftwareKey, signing: SoftwareKey) => {
      const st = verifyKel([...kel, ev], T);
      return [...kel, ev, await createDelegation(st, root, signing.publicKey(), T)];
    };
    const icp = await createInception(r0, d(r1), T, d(b0));
    const s1 = generateSoftwareKey();
    const base = [icp, await createDelegation(verifyKel([icp], T), r0, s1.publicKey(), T)];
    const a = as(r0, s1, base);
    expect((await register(fixed, a, T)).statusCode).toBe(200);
    // The fallback root alone takes it over; then it is retired and its KEL expires.
    const s2 = generateSoftwareKey();
    const byFallback = await extend(base, await createRotation(verifyKel(base, T), b0, d(r1), T, d(b1)), b0, s2);
    const recovered = as(b0, s2, byFallback);
    expect((await register(fixed, recovered, T + 1)).json()).toEqual({ ok: true, status: 'rotated' });
    await unregistered(recovered, T + 2);
    await expire(a.aceId);
    expect(await fixed.redis.hmget(`ace:horizon:${a.aceId}`, 'epochSeq', 'reclaimSeq')).toEqual(['2', '2']);
    // A thief holding the stolen fallback root cannot re-fork at the reclaim point (it reveals no next root).
    const s4 = generateSoftwareKey();
    const refork = await extend(base, await createRotation(verifyKel(base, T), b0, d(r2), T, d(b1)), b0, s4);
    expect((await register(fixed, as(b0, s4, refork), T + 3)).json().error).toBe('kel_conflict');
    // The next root reclaims at the fallback rot's seq: a fork at the retired epoch start, before the epoch's own events.
    const s3 = generateSoftwareKey();
    const reclaimed = await extend(base, await createRotation(verifyKel(base, T), r1, d(r2), T), r1, s3);
    expect((await register(fixed, as(r1, s3, reclaimed), T + 3)).json()).toEqual({ ok: true, status: 'registered' });
  });

  it('legitimate re-registration extending the horizon accepted, and a rot recovery (01 rule 6)', async () => {
    const a = await newAgent(0, T);
    expect((await register(fixed, a, T)).statusCode).toBe(200);
    await unregistered(a, T + 1);
    await expire(a.aceId);
    const backup = a.id.exportPrivateKey();
    await a.id.delegate({ now: T });
    expect((await register(fixed, a, T + 2)).json()).toEqual({ ok: true, status: 'registered' });
    // The holder of the committed next root recovers from a copy of the log taken before that delegation.
    await unregistered(a, T + 3);
    await expire(a.aceId);
    const nextRoot = new SoftwareKey(fromBase64(backup.nextRootSeed!));
    const recovered = await SoftwareIdentity.recover(a.id.getKel(), nextRoot, { now: T });
    expect((await register(fixed, { ...a, id: recovered }, T + 4)).json()).toEqual({ ok: true, status: 'registered' });
  });
});

describe('A6 the permit issuer must be usable now', () => {
  it('permit signed after issuer notAfter is not_permitted', async () => {
    const issuer = await newAgent(), from = await newAgent();
    const t0 = now(); // not before the identities' inception
    let clock = t0;
    const r = await createTestRelay(11, {}, { clock: () => clock });
    try {
      await issuer.id.delegate({ now: t0, notAfter: t0 + 100 });
      expect((await register(r, issuer, t0)).statusCode).toBe(200);
      expect((await publish(r, issuer, { now: t0 })).statusCode).toBe(200);
      const p = await createPermit(issuer.id, from.aceId, { now: t0 });
      clock = t0 + 50;
      expect((await send(r, await packet(from, issuer), p)).statusCode).toBe(200);
      // Past the issuer's delegation notAfter the permit no longer admits anyone (01 rule 5).
      clock = t0 + 101;
      expect((await send(r, await packet(from, issuer), p)).json()).toEqual({ error: 'not_permitted', message: 'not permitted' });
    } finally {
      await r.close();
    }
  });
});

describe('A3 removed surface', () => {
  it('unknown route returns {error}', async () => {
    for (const [method, url] of [['GET', '/v1/nope'], ['GET', '/v1/capabilities'], ['GET', '/v1/openapi.json'], ['PUT', '/v1/webhook'], ['GET', '/']] as const) {
      const res = await relay.app.inject({ method, url });
      expect(res.statusCode).toBe(404);
      expect(res.json()).toEqual({ error: 'not_found' });
    }
  });

  it('a descriptor publication is charged once, not per republish', async () => {
    const a = await newAgent();
    expect((await registerFrom(relay, a, '192.0.2.77')).statusCode).toBe(200);
    expect((await publish(relay, a)).statusCode).toBe(200);
    const once = await networkBytes(relay, 'n:192.0.2.0/24');
    expect((await relay.app.inject({ method: 'POST', url: '/v1/descriptor', payload: await descriptorOf(a, { now: now() + 1 }) })).statusCode).toBe(200);
    expect(Math.abs((await networkBytes(relay, 'n:192.0.2.0/24')) - once)).toBeLessThan(64);
  });
});
