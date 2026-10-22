import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  RelayClient, SoftwareIdentity, SoftwareKey, createDescriptor, encodePayload, fromBase64, signingMessage, toBase64, verifyKel,
  type JSONObject, type KelEvent, type PublishedAgent, type SoftwareIdentityExport,
} from '@ace-protocol/sdk';
import {
  BAD_RELAY_URLS, RELAY_URL, block, createTestRelay, descriptorOf, newAgent, now, packet, publish, publishCard, register,
  registered, resign, send, unregister, type Agent, type TestRelay,
} from './helpers.js';

let relay: TestRelay;
beforeAll(async () => { relay = await createTestRelay(2); });
afterAll(async () => { await relay.close(); });

const get = (url: string) => relay.app.inject({ method: 'GET', url });
const post = (payload: unknown) => relay.app.inject({ method: 'POST', url: '/v1/descriptor', payload: payload as object });
/** 07 § Errors: stale_peer_binding is 401. */
const expectStale = (res: { statusCode: number; json(): any }) => {
  expect(res.json().error).toBe('stale_peer_binding');
  expect(res.statusCode).toBe(401);
};

/** Fork recovery (01 rule 6) from `copy`: rot (1) at `ts`, then a dlg (2) re-delegating `a`'s current signing key at the same seq. */
async function recoverRedelegating(a: Agent, copy: SoftwareIdentityExport, ts: number): Promise<Agent> {
  const nextRoot = new SoftwareKey(fromBase64(copy.nextRootSeed!));
  const kel = (await SoftwareIdentity.recover(copy.kel, nextRoot, { now: ts })).getKel().slice(0, 2);
  const signingSeed = a.id.exportPrivateKey().signingSeed;
  const k = new SoftwareKey(fromBase64(signingSeed)).publicKey();
  const prev = verifyKel(kel, ts).lastHash;
  const eb = encodePayload('dlg', '2', String(ts), prev, 'ml-dsa-65', k, '');
  const dlg: KelEvent = {
    t: 'dlg', seq: 2, ts, prev, key: { scheme: 'ml-dsa-65', publicKey: toBase64(k) },
    sig: { scheme: 'ml-dsa-65', value: toBase64(await nextRoot.sign(signingMessage(a.aceId, ts, null, eb), 'kel')) },
  };
  return { ...a, id: SoftwareIdentity.fromExport({ rootSeed: copy.nextRootSeed, signingSeed, kel: [...kel, dlg] }, ts) };
}

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
    // All after the log's last event (createDescriptor dates a descriptor no earlier).
    const t = now() + 20;
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

  // Review 2026-10-21 SP2: a stored descriptor whose kel is not the registered KEL is absent (07 § Descriptors and cards).
  it('a descriptor under a superseded KEL is absent: not served, and no bar to the new KEL\'s descriptor', async () => {
    const a = await registered(relay);
    // A holder of the signing key dates a descriptor as far ahead as verification allows.
    const ahead = now() + 250;
    expect((await publish(relay, a, { now: ahead })).statusCode).toBe(200);
    expect((await get(`/v1/descriptor/${a.aceId}`)).json().descriptor.issuedAt).toBe(ahead);
    await a.id.delegate();
    expect((await register(relay, a, now() + 1)).json().status).toBe('rotated');
    expect((await get(`/v1/descriptor/${a.aceId}`)).json().error).toBe('unknown_peer');
    // The owner's descriptor under the new KEL replaces it although older.
    const t = now() + 3;
    expect((await publish(relay, a, { now: t })).json()).toEqual({ ok: true });
    const served = (await get(`/v1/descriptor/${a.aceId}`)).json();
    expect(served.descriptor.issuedAt).toBe(t);
    expect(served.kel).toEqual(a.id.getKel());
    // Under one KEL issuedAt still only moves forward.
    expect((await publish(relay, a, { now: t - 1 })).json().error).toBe('stale_descriptor');
  });

  // 04 § Verification step 3 (SP12): a descriptor signed before its delegating dlg is stale_peer_binding, whatever the
  // relay stores. The relay holds no dlg-ts horizon of its own: the SDK's verification refuses these on every path.
  it('a fork recovery that re-delegates the same key at the same seq cannot replay a descriptor of the superseded branch', async () => {
    const a = await registered(relay); // icp (0), dlg (1)
    const copy = a.id.exportPrivateKey(); // a copy of the log holding the committed next root
    const t0 = now();
    await a.id.delegate({ now: t0 }); // dlg (2) of key K
    expect((await register(relay, a, t0 + 1)).json().status).toBe('rotated');
    const old = await descriptorOf(a, { now: t0 });
    expect((await post(old)).statusCode).toBe(200);
    const ts = t0 + 5;
    const recovered = await recoverRedelegating(a, copy, ts);
    expect((await register(relay, recovered, ts)).json().status).toBe('rotated');
    // The superseded branch's descriptor names the recovered KEL's seq and key but predates its dlg.
    expectStale(await post({ kel: recovered.id.getKel(), descriptor: old.descriptor }));
    expect((await get(`/v1/descriptor/${a.aceId}`)).json().error).toBe('unknown_peer');
    expect((await publish(relay, recovered, { now: ts })).json()).toEqual({ ok: true });
    expect((await get(`/v1/descriptor/${a.aceId}`)).json().descriptor.issuedAt).toBe(ts);
  });

  it('the replay is refused with no stored descriptor here', async () => {
    const a = await registered(relay);
    const copy = a.id.exportPrivateKey();
    const t0 = now();
    await a.id.delegate({ now: t0 }); // never shown to this relay
    const old = await descriptorOf(a, { now: t0 });
    const ts = t0 + 5;
    const recovered = await recoverRedelegating(a, copy, ts);
    expect((await register(relay, recovered, ts)).statusCode).toBe(200);
    expect(await relay.redis.exists(`ace:descriptor:${a.aceId}`)).toBe(0);
    expectStale(await post({ kel: recovered.id.getKel(), descriptor: old.descriptor }));
    expect((await get(`/v1/descriptor/${a.aceId}`)).json().error).toBe('unknown_peer');
  });

  it('the replay is refused after unregister and re-registration under the recovered KEL', async () => {
    const a = await registered(relay);
    const copy = a.id.exportPrivateKey();
    const t0 = now();
    await a.id.delegate({ now: t0 });
    expect((await register(relay, a, t0 + 1)).json().status).toBe('rotated');
    const old = await descriptorOf(a, { now: t0 });
    expect((await post(old)).statusCode).toBe(200);
    expect((await unregister(relay, a, t0 + 2)).statusCode).toBe(200);
    const ts = t0 + 5;
    const recovered = await recoverRedelegating(a, copy, ts);
    expect((await register(relay, recovered, ts)).statusCode).toBe(200);
    // The issuedAt and digest kept across unregister would admit the identical bytes; verification does not.
    expectStale(await post({ kel: recovered.id.getKel(), descriptor: old.descriptor }));
    expect((await get(`/v1/descriptor/${a.aceId}`)).json().error).toBe('unknown_peer');
    expect((await publish(relay, recovered, { now: ts })).json()).toEqual({ ok: true });
  });

  it('after a fork recovery the owner\'s descriptor replaces one a stolen key dated ahead, from the new dlg\'s ts on', async () => {
    const a = await registered(relay);
    const copy = a.id.exportPrivateKey();
    const t0 = now();
    // A holder of the stolen signing key dates a descriptor as far ahead as verification allows.
    expect((await publish(relay, a, { now: t0 + 250 })).statusCode).toBe(200);
    const ts = t0 + 2;
    const owner = { ...a, id: await SoftwareIdentity.recover(copy.kel, new SoftwareKey(fromBase64(copy.nextRootSeed!)), { now: ts }) };
    expect((await register(relay, owner, ts)).json().status).toBe('rotated');
    // Signed before the new dlg: refused by verification, not by the stored (absent) descriptor.
    const early = await descriptorOf(owner, { now: ts });
    expectStale(await post({ kel: early.kel, descriptor: await resign(owner, 'agent-descriptor', { ...early.descriptor, issuedAt: ts - 1 }) }));
    expect((await publish(relay, owner, { now: ts })).json()).toEqual({ ok: true });
    const served = (await get(`/v1/descriptor/${a.aceId}`)).json();
    expect(served.descriptor.issuedAt).toBe(ts);
    expect(served.kel).toEqual(owner.id.getKel());
  });

  // 02 § Relay URL: the ACE HTTPS host grammar (C1).
  it.each(BAD_RELAY_URLS)('refuses a descriptor routing to %s', async (bad) => {
    const a = await registered(relay);
    const d = await descriptorOf(a);
    const res = await post({ kel: d.kel, descriptor: await resign(a, 'agent-descriptor', { ...d.descriptor, relays: [RELAY_URL, bad] }) });
    expect(res.statusCode).toBe(401);
    expect(res.json().error).toBe('invalid_authorization');
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

    const page = await get('/v1/cards?profile=x%3Adeep%3A1');
    const client = new RelayClient(RELAY_URL, { fetch: async () => new Response(page.body, { status: 200, headers: { 'content-type': 'application/json' } }) });
    expect((await client.directory({ profile: 'x:deep:1' })).cards.map((x) => x.aceId)).toEqual([a.aceId]);
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
