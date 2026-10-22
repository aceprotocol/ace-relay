// fp-minimal (contract A3, A6, A7, A10): stranger quotas, storage bounds, liveness of permit issuers, unknown routes.
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  MAX_PACKET_BYTES, OFFLINE_WINDOW_SECONDS, SoftwareIdentity, SoftwareKey, createPermit, createRegistrationRequest, fromBase64,
} from '@ace-protocol/sdk';
import {
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
      expect(await r.messageStore.registrationNetworkBytes(net)).toBe(kelBytes);
      // The descriptor is charged to the network the identity registered from, wherever it is published from.
      expect((await publish(r, a)).statusCode).toBe(200);
      const withDescriptor = await r.messageStore.registrationNetworkBytes(net);
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
      const before = await r.messageStore.registrationNetworkBytes(net);
      const un = await r.app.inject({ method: 'POST', url: '/v1/unregister', headers: await authHeaders(a, { action: 'unregister' }, now() + 2) });
      expect(un.statusCode).toBe(200);
      expect(before - (await r.messageStore.registrationNetworkBytes(net))).toBe(withDescriptor - kelBytes - HORIZON_BYTES);
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

  const expire = (aceId: string) => relay.redis.del(`ace:identity:${aceId}`, `ace:descriptor:${aceId}`);
  const unregistered = async (a: Agent, at: number) => expect((await unregister(relay, a, at)).statusCode).toBe(200);

  it('rollback after expiry refused', async () => {
    // A superseded delegation key (same root epoch) and a superseded root (an older epoch).
    const a = await newAgent();
    const t = now();
    expect((await register(relay, a, t)).statusCode).toBe(200);
    const oldDelegation = SoftwareIdentity.fromExport(a.id.exportPrivateKey());
    await a.id.delegate();
    const oldRoot = SoftwareIdentity.fromExport(a.id.exportPrivateKey());
    await a.id.rotate();
    expect((await register(relay, a, t + 1)).json()).toEqual({ ok: true, status: 'rotated' });
    await unregistered(a, t + 2);
    await expire(a.aceId);
    const old = (id: SoftwareIdentity) => ({ ...a, id });
    expect((await register(relay, old(oldRoot), t + 3)).json().error).toBe('kel_conflict');
    expect((await register(relay, old(oldDelegation), t + 3)).json().error).toBe('kel_conflict');
    // In the same epoch: a strict prefix of the retained epoch is stale_seq, a dlg fork kel_conflict.
    const b = await newAgent();
    expect((await register(relay, b, t)).statusCode).toBe(200);
    const bOld = SoftwareIdentity.fromExport(b.id.exportPrivateKey());
    await b.id.delegate();
    expect((await register(relay, b, t + 1)).json()).toEqual({ ok: true, status: 'rotated' });
    await unregistered(b, t + 2);
    await expire(b.aceId);
    expect((await register(relay, { ...b, id: bOld }, t + 3)).json().error).toBe('stale_seq');
    await bOld.delegate();
    expect((await register(relay, { ...b, id: bOld }, t + 3)).json().error).toBe('kel_conflict');
  });

  it('a forked dlg-only candidate after epochSeq is refused', async () => {
    const a = await newAgent();
    const t = now();
    const fork = SoftwareIdentity.fromExport(a.id.exportPrivateKey());
    await a.id.delegate();
    expect((await register(relay, a, t)).statusCode).toBe(200);
    await unregistered(a, t + 1);
    await expire(a.aceId);
    // Same epoch start, then delegations the retired log never had: longer than it, no rot.
    await fork.delegate();
    await fork.delegate();
    expect(fork.getKel()).toHaveLength(a.id.getKel().length + 1);
    expect((await register(relay, { ...a, id: fork }, t + 2)).json().error).toBe('kel_conflict');
  });

  it('legitimate re-registration extending the horizon accepted, and a rot recovery (01 rule 6)', async () => {
    const a = await newAgent();
    const t = now();
    expect((await register(relay, a, t)).statusCode).toBe(200);
    await unregistered(a, t + 1);
    await expire(a.aceId);
    const backup = a.id.exportPrivateKey();
    await a.id.delegate();
    expect((await register(relay, a, t + 2)).json()).toEqual({ ok: true, status: 'registered' });
    // The holder of the committed next root recovers from a copy of the log taken before that delegation.
    await unregistered(a, t + 3);
    await expire(a.aceId);
    const nextRoot = new SoftwareKey(fromBase64(backup.nextRootSeed!));
    const recovered = await SoftwareIdentity.recover(a.id.getKel(), nextRoot);
    expect((await register(relay, { ...a, id: recovered }, t + 4)).json()).toEqual({ ok: true, status: 'registered' });
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
    const once = await relay.messageStore.registrationNetworkBytes('n:192.0.2.0/24');
    expect((await relay.app.inject({ method: 'POST', url: '/v1/descriptor', payload: await descriptorOf(a, { now: now() + 1 }) })).statusCode).toBe(200);
    expect(Math.abs((await relay.messageStore.registrationNetworkBytes('n:192.0.2.0/24')) - once)).toBeLessThan(64);
  });
});
