import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { RelayClient, createDescriptor, type JSONObject, type PublishedAgent } from '@ace-protocol/sdk';
import {
  RELAY_URL, block, createTestRelay, descriptorOf, newAgent, now, packet, publish, publishCard, register, registered, send, type TestRelay,
} from './helpers.js';

let relay: TestRelay;
beforeAll(async () => { relay = await createTestRelay(2); });
afterAll(async () => { await relay.close(); });

const get = (url: string) => relay.app.inject({ method: 'GET', url });

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
    tampered.descriptor.relays = [RELAY_URL, 'https://elsewhere.test'];
    expect((await relay.app.inject({ method: 'POST', url: '/v1/descriptor', payload: tampered })).json().error).toBe('invalid_authorization');
    expect((await relay.app.inject({ method: 'POST', url: '/v1/descriptor', payload: d })).statusCode).toBe(200);
    expect((await relay.app.inject({ method: 'POST', url: '/v1/descriptor', payload: d })).statusCode).toBe(200); // idempotent
    expect((await publish(relay, a, { now: t - 10 })).json().error).toBe('stale_descriptor');
    const sameSecond = await descriptorOf(a, { now: t, relays: [RELAY_URL, 'https://elsewhere.test'] });
    expect((await relay.app.inject({ method: 'POST', url: '/v1/descriptor', payload: sameSecond })).json().error).toBe('stale_descriptor');
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
      ext: { 'x:deep:1': nest(29) },
    });
    const over: PublishedAgent = structuredClone(ok);
    over.descriptor.ext = { 'x:deep:1': nest(30) };
    const refused = await post(over);
    expect(refused.statusCode).toBe(401);
    expect(refused.json()).toMatchObject({ error: 'invalid_authorization', message: expect.stringMatching(/depth 32/) });
    expect((await post(ok)).statusCode).toBe(200);
    expect((await publishCard(relay, a, { listed: true })).statusCode).toBe(200);

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
