import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createRegistrationRequest } from '@ace-protocol/sdk';
import {
  BACKDATED, authHeaders, block, createTestRelay, descriptorOf, inbox, newAgent, now, packet, permit, publish, publishCard, register, registered, send,
  type TestRelay,
  RELAY_URL,
} from './helpers.js';

let relay: TestRelay;
beforeAll(async () => { relay = await createTestRelay(1); });
afterAll(async () => { await relay.close(); });

describe('POST /v1/register', () => {
  it('registers, is idempotent, refreshes and rotates', async () => {
    const a = await newAgent();
    const t = now();
    const req = await createRegistrationRequest(a.id, { audience: RELAY_URL, timestamp: t });
    const first = await relay.app.inject({ method: 'POST', url: '/v1/register', payload: req });
    expect(first.json()).toEqual({ ok: true, status: 'registered' });
    expect((await relay.app.inject({ method: 'POST', url: '/v1/register', payload: req })).json()).toEqual({ ok: true, status: 'idempotent' });
    expect((await register(relay, a, t + 1)).json()).toEqual({ ok: true, status: 'refreshed' });
    await a.id.delegate();
    expect((await register(relay, a, t + 2)).json()).toEqual({ ok: true, status: 'rotated' });
    // An older timestamp, or the superseded KEL, is refused.
    expect((await register(relay, a, t + 1)).json().error).toBe('identity_conflict');
    expect((await relay.app.inject({ method: 'POST', url: '/v1/register', payload: { ...req, timestamp: t + 5 } })).json().error)
      .toBe('invalid_authorization');
  });

  it('rejects malformed, stale and mismatched requests', async () => {
    const a = await newAgent(BACKDATED);
    const req = await createRegistrationRequest(a.id, { audience: RELAY_URL });
    const post = (payload: unknown) => relay.app.inject({ method: 'POST', url: '/v1/register', payload: payload as object });
    expect((await post({ ...req, extra: 1 })).json().error).toBe('invalid_registration');
    expect((await post(await createRegistrationRequest(a.id, { audience: RELAY_URL, timestamp: now() - 400 }))).json().error).toBe('stale_timestamp');
    // L2: a request signed for another relay is refused (no relay can replay it here)
    const other = await post(await createRegistrationRequest(a.id, { audience: 'https://other-relay.test' }));
    expect([other.statusCode, other.json().error]).toEqual([401, 'invalid_signature']);
    const b = await newAgent();
    expect((await post({ ...req, aceId: b.aceId })).json().error).toBe('invalid_registration');
    const res = await relay.app.inject({ method: 'POST', url: '/v1/register', headers: { 'content-type': 'application/json' }, payload: '{' });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_argument');
  });

  it('rate-limits registrations and publications by registration network; a trusted network has its own limit', async () => {
    const limited = await createTestRelay(13, { registerRateLimit: 1, trustedRegisterRateLimit: 2, trustedRegistrationNetworks: ['10.0.0.0/8'] });
    try {
      const reg = async (remoteAddress: string) => {
        const a = await newAgent();
        const res = await limited.app.inject({ method: 'POST', url: '/v1/register', payload: await createRegistrationRequest(a.id, { audience: RELAY_URL }), remoteAddress });
        return { a, status: res.statusCode };
      };
      // two /24s inside the trusted CIDR share one bucket of TRUSTED_REGISTER_RATE_LIMIT
      const first = await reg('10.1.2.3'), second = await reg('10.200.0.1');
      expect([first.status, second.status, (await reg('10.3.3.3')).status]).toEqual([200, 200, 429]);
      // an untrusted network keeps REGISTER_RATE_LIMIT
      expect([(await reg('192.0.2.1')).status, (await reg('192.0.2.2')).status]).toEqual([200, 429]);
      // descriptor publications: the same attribution, a separate bucket
      const pub = async (a: typeof first.a, remoteAddress: string) =>
        (await limited.app.inject({ method: 'POST', url: '/v1/descriptor', payload: await descriptorOf(a), remoteAddress })).statusCode;
      expect([await pub(first.a, '10.1.2.3'), await pub(second.a, '10.9.9.9'), await pub(first.a, '10.1.2.3')]).toEqual([200, 200, 429]);
      // card publications: the same attribution, a bucket of their own
      const card = async (a: typeof first.a, remoteAddress: string, t: number) => (await publishCard(limited, a, { now: t }, remoteAddress)).statusCode;
      expect([await card(first.a, '10.1.2.3', now()), await card(second.a, '10.9.9.9', now()), await card(first.a, '10.1.2.3', now() + 1)])
        .toEqual([200, 200, 429]);
    } finally {
      await limited.close();
    }
  });

  it('rate-limits registrations per coarse client network (IPv6 by /56)', async () => {
    const limited = await createTestRelay(13, { registerRateLimit: 1 });
    try {
      const a = await newAgent(), b = await newAgent();
      const at = (remoteAddress: string, payload: object) => limited.app.inject({ method: 'POST', url: '/v1/register', payload, remoteAddress });
      expect((await at('2001:db8:1:2::1', await createRegistrationRequest(a.id, { audience: RELAY_URL }))).statusCode).toBe(200);
      const res = await at('2001:db8:1:2:ffff::9', await createRegistrationRequest(b.id, { audience: RELAY_URL }));
      expect(res.statusCode).toBe(429);
      expect(res.headers['retry-after']).toMatch(/^\d+$/);
      // Another /64 of the same /56 shares the bucket; another /56 does not.
      expect((await at('2001:db8:1:3::1', await createRegistrationRequest(b.id, { audience: RELAY_URL }))).statusCode).toBe(429);
      expect((await at('2001:db8:1:100::1', await createRegistrationRequest(b.id, { audience: RELAY_URL }))).statusCode).toBe(200);
    } finally {
      await limited.close();
    }
  });
});

describe('POST /v1/unregister', () => {
  it('deletes queue, descriptor, card record and blocks; keeps the KEL barrier and the handle binding', async () => {
    const a = await registered(relay), b = await registered(relay);
    expect((await publish(relay, a)).statusCode).toBe(200);
    expect((await publishCard(relay, a, { contact: 'open', handle: 'leaver' })).statusCode).toBe(200);
    expect((await send(relay, await packet(b, a), await permit(a, b))).statusCode).toBe(200);
    expect((await block(relay, a, b.aceId, true, 1)).statusCode).toBe(200);

    const res = await relay.app.inject({ method: 'POST', url: '/v1/unregister', headers: await authHeaders(a, { action: 'unregister' }, now() + 1) });
    expect(res.json()).toEqual({ ok: true });
    const keys = (await relay.redis.keys(`*${a.aceId}*`)).filter((k) => !/^ace:(replay|rate):/.test(k)).sort();
    expect(keys).toEqual([`ace:card:${a.aceId}`, `ace:descriptor:${a.aceId}`, `ace:handleof:${a.aceId}`, `ace:horizon:${a.aceId}`, `ace:identity:${a.aceId}`]);
    for (const k of [`ace:descriptor:${a.aceId}`, `ace:card:${a.aceId}`]) {
      expect((await relay.redis.hkeys(k)).sort()).toEqual(['digest', 'issuedAt']);
    }
    expect(await relay.redis.get('ace:handle:leaver')).toBe(a.aceId);
    expect((await relay.app.inject({ method: 'GET', url: '/v1/handles/leaver' })).statusCode).toBe(404);
    expect((await inbox(relay, a)).json().error).toBe('not_registered');
    expect((await send(relay, await packet(b, a), await permit(a, b))).json().error).toBe('not_permitted');

    // The barrier: re-registration needs a newer timestamp.
    expect((await register(relay, a, now() - 10)).json().error).toBe('identity_conflict');
    expect((await register(relay, a, now() + 2)).json()).toEqual({ ok: true, status: 'registered' });
  });

  it('requires a timestamp newer than the registration', async () => {
    const a = await newAgent();
    await register(relay, a, now() + 100);
    const res = await relay.app.inject({ method: 'POST', url: '/v1/unregister', headers: await authHeaders(a, { action: 'unregister' }) });
    expect(res.json().error).toBe('identity_conflict');
  });
});

describe('authentication', () => {
  it('checks registration, seq, audience, freshness and nonces', async () => {
    const a = await registered(relay, BACKDATED);
    const stranger = await newAgent();
    const get = (headers: Record<string, string>) => relay.app.inject({ method: 'GET', url: '/v1/inbox?limit=100', headers });
    const req = { action: 'inbox' as const, since: '-', limit: 100 };
    expect((await get(await authHeaders(stranger, req))).json().error).toBe('not_registered');
    expect((await get({})).json().error).toBe('invalid_argument');
    expect((await get(await authHeaders(a, req, now(), 'https://other.test'))).json().error).toBe('invalid_signature');
    expect((await get(await authHeaders(a, req, now() - 400))).json().error).toBe('stale_timestamp');
    expect((await get(await authHeaders(a, { ...req, limit: 5 }))).json().error).toBe('invalid_signature');
    const h = await authHeaders(a, req);
    expect((await get(h)).statusCode).toBe(200);
    const again = await get(h);
    expect(again.statusCode).toBe(409);
    expect(again.json().error).toBe('replay');
    expect(await relay.redis.ttl(`ace:replay:${a.aceId}:${h['x-ace-nonce']}`)).toBeGreaterThan(600);
    // A delegation newer than the registered one is future_seq; after registering it, the old one is stale_seq.
    const old = await authHeaders(a, req);
    await a.id.delegate();
    expect((await get(await authHeaders(a, req))).json().error).toBe('future_seq');
    await register(relay, a, now() + 1);
    expect((await get(old)).json().error).toBe('stale_seq');
  });
});
