// End to end through real relays over loopback HTTP with the real SDK NetworkClient: contact → accept → message →
// receipt, within one relay and across two. Each relay has an HTTPS public URL (its audience and descriptor route);
// the clients' fetch maps that origin to the relay's loopback listener, as DNS and TLS termination would.
// (A loopback http:// route would need allowLoopbackRelays, which the SDK Inbox ignores for contact sources.)
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import {
  MemoryStore, NetworkClient, RelayClient, SoftwareIdentity, type NetworkClientOptions, type ParsedMessage,
} from '@ace-protocol/sdk';
import { createTestRelay, type TestRelay } from './helpers.js';

// Each test generates several ML-DSA identities; under the full parallel run that exceeds the 5 s default.
vi.setConfig({ testTimeout: 30_000 });

let relayA: TestRelay, relayB: TestRelay;
const urlA = 'https://relay-a.test', urlB = 'https://relay-b.test';
const listeners = new Map<string, string>();

async function serve(db: number, publicRelayUrl: string): Promise<TestRelay> {
  const r = await createTestRelay(db, { publicRelayUrl });
  await r.app.listen({ host: '127.0.0.1', port: 0 });
  listeners.set(publicRelayUrl, `http://127.0.0.1:${(r.app.server.address() as { port: number }).port}`);
  return r;
}

/** Real HTTP to the relay listening for that public origin. */
const mappedFetch: typeof fetch = (input, init) => {
  const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
  const target = listeners.get(url.origin);
  if (!target) return Promise.reject(new Error(`no relay at ${url.origin}`));
  return fetch(target + url.pathname + url.search, init);
};

beforeAll(async () => { relayA = await serve(8, urlA); relayB = await serve(9, urlB); });
afterAll(async () => { await relayA.close(); await relayB.close(); });

interface Peer { client: NetworkClient; aceId: string; received: ParsedMessage[] }

async function peer(home: string, o: Partial<NetworkClientOptions> = {}): Promise<Peer> {
  const identity = await SoftwareIdentity.generate();
  const received: ParsedMessage[] = [];
  const relay = (url: string) => new RelayClient(url, { fetch: mappedFetch });
  const client = await NetworkClient.open({
    identity, store: new MemoryStore(), relay: relay(home), profiles: ['text'],
    foreignRelay: relay, onMessage: (m) => { received.push(m); }, ...o,
  });
  await client.publish(); // registers first
  return { client, aceId: identity.getACEId(), received };
}

describe('NetworkClient through the relay', () => {
  it('one relay: discovery, handle, explicit accept, message, receipt, block', async () => {
    const alice = await peer(urlA, { contact: 'open', listed: true, handle: 'alice' });
    const bob = await peer(urlA);

    expect((await bob.client.discover()).agents.map((a) => a.descriptor.aceId)).toEqual([alice.aceId]);
    expect((await bob.client.lookup('@alice@relay-a.test')).descriptor.aceId).toBe(alice.aceId);
    expect((await bob.client.lookupCard('@alice@relay-a.test')).record).toMatchObject({ handle: 'alice', home: urlA, contact: 'open' });
    // bob takes no contact requests from strangers: alice cannot reach him first.
    expect((await alice.client.lookupCard(bob.aceId)).record).toMatchObject({ contact: 'closed', listed: false });
    await expect(alice.client.connect(bob.aceId, { profile: 'ace:text:1' })).rejects.toMatchObject({ code: 'not_permitted' });

    await bob.client.connect(alice.aceId, { profile: 'ace:text:1', note: 'hi from bob' });
    const [request] = await alice.client.pull();
    expect(request).toMatchObject({ kind: 'contact', event: { stranger: true, body: { kind: 'request', note: 'hi from bob' } } });
    expect((await alice.client.requests()).map((r) => r.from)).toEqual([bob.aceId]);
    await alice.client.accept(bob.aceId);
    expect((await bob.client.pull())[0]).toMatchObject({ kind: 'contact', event: { body: { kind: 'accepted' } } });
    expect((await bob.client.admission.get(alice.aceId))!.status).toBe('admitted');

    // Every registered identity's descriptor can be looked up by ACE ID.
    expect((await alice.client.agent(bob.aceId, { refresh: true })).descriptor.aceId).toBe(bob.aceId);

    const entry = await bob.client.send(alice.aceId, 'ace:text:1', { message: 'hello alice' });
    expect(entry.status).toBe('pending');
    expect((await alice.client.pull())[0].kind).toBe('delivered');
    expect(alice.received.map((m) => m.body.message)).toEqual(['hello alice']);
    expect((await bob.client.pull())[0].kind).toBe('receipt');
    expect((await bob.client.outbox.get(entry.messageId))!.status).toBe('delivered');
    expect(await relayA.redis.xlen(`ace:inbox:${alice.aceId}`)).toBe(0); // acknowledged

    await alice.client.block(bob.aceId);
    const refused = await bob.client.send(alice.aceId, 'ace:text:1', { message: 'still there?' });
    expect(refused).toMatchObject({ status: 'pending', code: 'not_permitted' });
    await Promise.all([alice.client.close(), bob.client.close()]);
  });

  it('two relays: each endpoint routes to the other\'s home relay', async () => {
    const alice = await peer(urlA, { contact: 'open', acceptProfiles: ['ace:text:1'] });
    const carol = await peer(urlB);
    const aliceAgent = await new RelayClient(urlA, { fetch: mappedFetch }).getDescriptor(alice.aceId);

    await carol.client.connect(aliceAgent, { profile: 'ace:text:1' });
    expect(await relayA.redis.xlen(`ace:inbox:${alice.aceId}`)).toBe(1);
    expect((await alice.client.pull())[0]).toMatchObject({ kind: 'contact', event: { body: { kind: 'request' } } });
    expect((await alice.client.admission.get(carol.aceId))!.status).toBe('admitted'); // acceptProfiles rule
    expect((await carol.client.pull())[0]).toMatchObject({ kind: 'contact', event: { body: { kind: 'accepted' } } });

    const entry = await carol.client.send(alice.aceId, 'ace:text:1', { message: 'across relays' });
    expect((await alice.client.pull())[0].kind).toBe('delivered');
    expect(alice.received.map((m) => m.body.message)).toEqual(['across relays']);
    expect((await carol.client.pull())[0].kind).toBe('receipt');
    expect((await carol.client.outbox.get(entry.messageId))!.status).toBe('delivered');

    const back = await alice.client.send(carol.aceId, 'ace:text:1', { message: 'and back' });
    expect((await carol.client.pull())[0].kind).toBe('delivered');
    expect(carol.received.map((m) => m.body.message)).toEqual(['and back']);
    expect((await alice.client.pull())[0].kind).toBe('receipt');
    expect((await alice.client.outbox.get(back.messageId))!.status).toBe('delivered');
    await Promise.all([alice.client.close(), carol.client.close()]);
  });

  it('follow() receives over the listen stream', async () => {
    const alice = await peer(urlB, { contact: 'open', acceptProfiles: ['ace:text:1'] });
    const dave = await peer(urlB);
    await dave.client.connect(alice.aceId, { profile: 'ace:text:1' });
    await alice.client.pull();
    await dave.client.pull();
    const ctl = new AbortController();
    const outcomes = alice.client.follow({ signal: ctl.signal });
    const next = outcomes.next();
    await dave.client.send(alice.aceId, 'ace:text:1', { message: 'live' });
    expect((await next).value).toMatchObject({ kind: 'delivered' });
    expect(alice.received.at(-1)!.body.message).toBe('live');
    ctl.abort();
    await outcomes.return(undefined);
    await Promise.all([alice.client.close(), dave.client.close()]);
  });
});
