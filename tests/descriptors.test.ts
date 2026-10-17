import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { RelayClient, createDescriptor, type JSONObject, type PublishedAgent } from '@ace-protocol/sdk';
import {
  RELAY_URL, block, createTestRelay, descriptorOf, newAgent, now, packet, permit, publish, published, register, registered, send, type TestRelay,
} from './helpers.js';

let relay: TestRelay;
beforeAll(async () => { relay = await createTestRelay(2); });
afterAll(async () => { await relay.close(); });

const get = (url: string) => relay.app.inject({ method: 'GET', url });
const resolve = (payload: object) => relay.app.inject({ method: 'POST', url: '/v1/descriptor/resolve', payload });

describe('POST /v1/descriptor', () => {
  it('requires registration, the registered KEL and this relay in relays', async () => {
    const a = await newAgent();
    expect((await publish(relay, a)).json().error).toBe('not_registered');
    await register(relay, a);
    expect((await publish(relay, a, { relays: ['https://elsewhere.test'] })).json().error).toBe('invalid_argument');
    expect((await publish(relay, a)).json()).toEqual({ ok: true });
    await a.id.delegate();
    expect((await publish(relay, a)).json().error).toBe('kel_conflict');
  });

  it('rejects an invalid document and keeps only newer descriptors', async () => {
    const a = await registered(relay);
    const t = now() - 10;
    const d = await descriptorOf(a, { now: t });
    const tampered = structuredClone(d);
    tampered.descriptor.visibility = 'public';
    expect((await relay.app.inject({ method: 'POST', url: '/v1/descriptor', payload: tampered })).json().error).toBe('invalid_authorization');
    expect((await relay.app.inject({ method: 'POST', url: '/v1/descriptor', payload: d })).statusCode).toBe(200);
    expect((await relay.app.inject({ method: 'POST', url: '/v1/descriptor', payload: d })).statusCode).toBe(200); // idempotent
    expect((await publish(relay, a, { now: t - 10 })).json().error).toBe('stale_descriptor');
    const sameSecond = await descriptorOf(a, { now: t, visibility: 'public' });
    expect((await relay.app.inject({ method: 'POST', url: '/v1/descriptor', payload: sameSecond })).json().error).toBe('stale_descriptor');
  });

  it('claims a handle only as the primary relay; a taken handle is refused; private releases it', async () => {
    const a = await registered(relay), b = await registered(relay), c = await registered(relay);
    expect((await publish(relay, a, { visibility: 'public', handle: 'alpha' })).statusCode).toBe(200);
    expect((await get('/v1/handles/alpha')).json().descriptor.aceId).toBe(a.aceId);
    expect((await publish(relay, b, { visibility: 'public', handle: 'alpha', now: now() + 1 })).json().error).toBe('handle_taken');
    // Not relays[0]: stored, handle not claimed.
    expect((await publish(relay, c, { visibility: 'public', handle: 'gamma', relays: ['https://primary.test', RELAY_URL] })).statusCode).toBe(200);
    expect((await get('/v1/handles/gamma')).statusCode).toBe(404);
    expect((await get(`/v1/descriptor/${c.aceId}`)).statusCode).toBe(200);
    // Renaming releases the old handle; going private releases everything.
    expect((await publish(relay, a, { visibility: 'public', handle: 'alpha2', now: now() + 2 })).statusCode).toBe(200);
    expect((await get('/v1/handles/alpha')).statusCode).toBe(404);
    expect((await publish(relay, b, { visibility: 'public', handle: 'alpha', now: now() + 3 })).statusCode).toBe(200);
    expect((await publish(relay, a, { now: now() + 4 })).statusCode).toBe(200);
    expect((await get('/v1/handles/alpha2')).statusCode).toBe(404);
    expect((await get(`/v1/descriptor/${a.aceId}`)).statusCode).toBe(404);
    expect(await relay.redis.zscore('ace:descriptors', a.aceId)).toBeNull();
  });
});

describe('depth (02 § JSON values)', () => {
  /** A JSON object whose deepest container is at depth `n` (its root at 0). */
  const nest = (n: number): JSONObject => (n === 0 ? {} : { a: nest(n - 1) });
  const post = (payload: unknown) => relay.app.inject({ method: 'POST', url: '/v1/descriptor', payload: payload as object });

  it('accepts a PublishedAgent at exactly MAX_JSON_DEPTH, refuses one level more, and serves the boundary agent in a page clients accept', async () => {
    const a = await registered(relay);
    const pk = (await a.vault.current())!;
    // ext (depth 2) → x:deep:1 (3) → 29 more levels: depth 32
    const ok = await createDescriptor(a.id, {
      relays: [RELAY_URL], prekey: { id: pk.id, publicKey: pk.publicKey }, profiles: [{ id: 'x:deep:1', digest: 'a'.repeat(64) }],
      visibility: 'public', ext: { 'x:deep:1': nest(29) },
    });
    const over: PublishedAgent = structuredClone(ok);
    over.descriptor.ext = { 'x:deep:1': nest(30) };
    const refused = await post(over);
    expect(refused.statusCode).toBe(401);
    expect(refused.json()).toMatchObject({ error: 'invalid_authorization', message: expect.stringMatching(/depth 32/) });
    expect((await post(ok)).statusCode).toBe(200);

    const page = await get('/v1/descriptors?profile=x%3Adeep%3A1');
    const client = new RelayClient(RELAY_URL, { fetch: async () => new Response(page.body, { status: 200, headers: { 'content-type': 'application/json' } }) });
    expect((await client.listDescriptors({ profile: 'x:deep:1' })).agents.map((x) => x.descriptor.aceId)).toEqual([a.aceId]);
  });

  it('a packet is closed-shape (depth 2); a deeper or deeply nested send body is invalid_packet, never a crash', async () => {
    const [a, b] = [await registered(relay), await registered(relay)];
    const p = await packet(a, b);
    for (const deep of [{ ...p, encryption: { ...p.encryption, prekey: nest(30) } }, '['.repeat(100_000) + ']'.repeat(100_000)]) {
      const res = typeof deep === 'string'
        ? await relay.app.inject({ method: 'POST', url: '/v1/send', headers: { 'content-type': 'application/json' }, payload: `{"packet":${deep}}` })
        : await send(relay, deep);
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe('invalid_packet');
    }
  });
});

describe('lookups', () => {
  it('GET /v1/descriptor/{aceId} serves only public, unexpired descriptors of active identities', async () => {
    const pub = await published(relay, { visibility: 'public' });
    const priv = await published(relay);
    expect((await get(`/v1/descriptor/${pub.aceId}`)).json().descriptor.aceId).toBe(pub.aceId);
    expect((await get(`/v1/descriptor/${priv.aceId}`)).json().error).toBe('unknown_peer');
    expect((await get('/v1/descriptor/not-an-id')).statusCode).toBe(404);
    await relay.redis.hset(`ace:descriptor:${pub.aceId}`, 'expiresAt', String(now() - 1));
    expect((await get(`/v1/descriptor/${pub.aceId}`)).statusCode).toBe(404);
  });

  it('POST /v1/descriptor/resolve returns private descriptors for a valid, unblocked permit', async () => {
    const target = await published(relay);
    const holder = await newAgent(); // need not be registered
    const p = await permit(target, holder);
    const ok = await resolve({ aceId: target.aceId, permit: p });
    expect(ok.statusCode).toBe(200);
    expect(ok.json().descriptor).toMatchObject({ aceId: target.aceId, visibility: 'private' });

    const other = await registered(relay);
    expect((await resolve({ aceId: other.aceId, permit: p })).json().error).toBe('unknown_peer'); // issuer != aceId
    expect((await resolve({ aceId: target.aceId, permit: { ...p, subject: other.aceId } })).json().error).toBe('unknown_peer');
    expect((await resolve({ aceId: target.aceId, permit: await permit(target, holder, { now: now() - 100, ttl: 50 }) })).json().error).toBe('unknown_peer');
    expect((await resolve({ aceId: target.aceId })).json().error).toBe('invalid_argument');
    expect((await resolve({ aceId: target.aceId, permit: p, extra: 1 })).json().error).toBe('invalid_argument');
    expect((await block(relay, target, holder.aceId, true, 1)).statusCode).toBe(200);
    expect((await resolve({ aceId: target.aceId, permit: p })).json().error).toBe('unknown_peer');
    expect((await block(relay, target, holder.aceId, false, 2)).statusCode).toBe(200);
    expect((await resolve({ aceId: target.aceId, permit: p })).statusCode).toBe(200);
    // A signing-key change at the issuer invalidates its earlier permits.
    await target.id.delegate();
    await register(relay, target, now() + 1);
    expect((await resolve({ aceId: target.aceId, permit: p })).json().error).toBe('unknown_peer');
  });
});

describe('GET /v1/descriptors', () => {
  it('lists public descriptors by ACE ID, filtered by profile, paged with a cursor', async () => {
    const dir = await createTestRelay(14);
    try {
      const agents = [];
      for (let i = 0; i < 5; i++) {
        const a = await registered(dir);
        expect((await publish(dir, a, { visibility: i === 4 ? 'private' : 'public' })).statusCode).toBe(200);
        if (i < 4) agents.push(a.aceId);
      }
      agents.sort();
      const page1 = (await dir.app.inject({ method: 'GET', url: '/v1/descriptors?limit=3' })).json();
      expect(page1.agents.map((x: any) => x.descriptor.aceId)).toEqual(agents.slice(0, 3));
      expect(page1.cursor).toBe(agents[2]);
      const page2 = (await dir.app.inject({ method: 'GET', url: `/v1/descriptors?limit=3&cursor=${page1.cursor}` })).json();
      expect(page2).toMatchObject({ cursor: null });
      expect(page2.agents.map((x: any) => x.descriptor.aceId)).toEqual(agents.slice(3));
      expect((await dir.app.inject({ method: 'GET', url: '/v1/descriptors?profile=ace:text:1' })).json().agents).toHaveLength(4);
      expect((await dir.app.inject({ method: 'GET', url: '/v1/descriptors?profile=ace:commerce:1' })).json()).toEqual({ agents: [], cursor: null });
      expect((await dir.app.inject({ method: 'GET', url: '/v1/descriptors?limit=0' })).json().error).toBe('invalid_argument');
      expect((await dir.app.inject({ method: 'GET', url: '/v1/descriptors?cursor=x' })).json().error).toBe('invalid_argument');
    } finally {
      await dir.close();
    }
  });
});

describe('POST /v1/blocks', () => {
  it('requires increasing revisions, keeps them after unblock, refuses self-blocks and caps tracked peers', async () => {
    const a = await registered(relay), b = await newAgent();
    expect((await block(relay, a, b.aceId, true, 5)).json()).toEqual({ ok: true });
    expect((await block(relay, a, b.aceId, false, 5)).json().error).toBe('stale_revision');
    expect((await block(relay, a, b.aceId, false, 6)).statusCode).toBe(200);
    expect((await block(relay, a, b.aceId, true, 6)).json().error).toBe('stale_revision');
    expect((await block(relay, a, a.aceId, true, 1)).json().error).toBe('invalid_argument');
    const res = await relay.app.inject({ method: 'POST', url: '/v1/blocks', payload: { peer: b.aceId, blocked: 'yes', revision: 1 } });
    expect(res.json().error).toBe('invalid_argument');
    const fields: string[] = [];
    for (let i = 0; i < 1023; i++) fields.push(`ace:sha256:${i.toString(16).padStart(64, '0')}`, '1:1');
    await relay.redis.hset(`ace:blocks:${a.aceId}`, ...fields);
    const c = await newAgent();
    expect((await block(relay, a, c.aceId, true, 1)).json().error).toBe('limit_exceeded');
    expect((await block(relay, a, b.aceId, true, 7)).statusCode).toBe(200); // a tracked peer is still updatable
  });
});
