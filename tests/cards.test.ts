// 07 § Descriptors and cards: card records, set-once handles, the listed directory and the open-contact send rule.
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { createRegistrationRequest, documentDigest, type CardBundle } from '@ace-protocol/sdk';
import { HORIZON_BYTES } from '../src/store/identity.js';
import {
  RELAY_URL, authHeaders, cardOf, createTestRelay, newAgent, now, packet, postCard, publish, publishCard, published, register,
  registered, send, type Agent, type TestRelay,
} from './helpers.js';

// Several tests generate many ML-DSA identities.
vi.setConfig({ testTimeout: 30_000 });

let relay: TestRelay;
beforeAll(async () => { relay = await createTestRelay(14); });
afterAll(async () => { await relay.close(); });

const get = (url: string) => relay.app.inject({ method: 'GET', url });
const unregister = async (a: Agent, t = now() + 1) =>
  relay.app.inject({ method: 'POST', url: '/v1/unregister', headers: await authHeaders(a, { action: 'unregister' }, t) });
const OTHER_HOME = 'https://other.test';

describe('POST /v1/card', () => {
  it('publishes and serves a card', async () => {
    const a = await registered(relay);
    const bundle = await cardOf(a, { card: { name: 'Alice' }, contact: 'open', listed: false });
    expect((await postCard(relay, bundle)).json()).toEqual({ ok: true });
    const res = await get(`/v1/card/${a.aceId}`);
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual(bundle);
    expect((await get(`/v1/card/${(await newAgent()).aceId}`)).json().error).toBe('unknown_peer');
    expect((await get('/v1/card/not-an-id')).json().error).toBe('unknown_peer');
  });

  it('requires registration, the registered KEL and a valid record', async () => {
    const a = await newAgent();
    expect((await publishCard(relay, a)).json().error).toBe('not_registered');
    await register(relay, a);
    const bundle = await cardOf(a);
    const tampered: CardBundle = structuredClone(bundle);
    tampered.card.contact = 'open';
    expect((await postCard(relay, tampered)).json().error).toBe('invalid_authorization');
    expect((await postCard(relay, { ...bundle, extra: 1 })).json().error).toBe('invalid_authorization');
    expect((await postCard(relay, bundle)).statusCode).toBe(200);
    await a.id.delegate();
    expect((await publishCard(relay, a, { now: now() + 1 })).json().error).toBe('kel_conflict');
  });

  it('card bytes are charged to the registration network and released at unregister', async () => {
    const a = await newAgent();
    expect((await relay.app.inject({
      method: 'POST', url: '/v1/register', remoteAddress: '192.0.2.40',
      payload: await createRegistrationRequest(a.id, { audience: RELAY_URL }),
    })).statusCode).toBe(200);
    const net = 'n:192.0.2.0/24';
    const before = await relay.messageStore.registrationNetworkBytes(net);
    const bundle = await cardOf(a, { card: { description: 'x'.repeat(200) } });
    expect((await postCard(relay, bundle)).statusCode).toBe(200);
    const charged = (await relay.messageStore.registrationNetworkBytes(net)) - before;
    expect(charged).toBe(Buffer.byteLength(JSON.stringify(bundle)));
    // A republish is charged by its difference, not again.
    const next = await cardOf(a, { card: { description: 'y'.repeat(200) }, now: now() + 1 });
    expect((await postCard(relay, next)).statusCode).toBe(200);
    const nextBytes = Buffer.byteLength(JSON.stringify(next));
    expect((await relay.messageStore.registrationNetworkBytes(net)) - before).toBe(nextBytes);
    const held = await relay.messageStore.registrationNetworkBytes(net);
    expect((await unregister(a, now() + 2)).statusCode).toBe(200);
    // The card's bytes are released at once (the KEL's lapse with the packet window; the horizon is charged for good).
    expect(held - (await relay.messageStore.registrationNetworkBytes(net))).toBe(nextBytes - HORIZON_BYTES);
  });
});

describe('ordering', () => {
  it('stale issuedAt is stale_descriptor', async () => {
    const a = await registered(relay);
    const t = now();
    expect((await publishCard(relay, a, { now: t })).statusCode).toBe(200);
    expect((await publishCard(relay, a, { now: t - 1 })).json().error).toBe('stale_descriptor');
  });

  it('equal issuedAt different claims is stale_descriptor', async () => {
    const a = await registered(relay);
    const t = now();
    expect((await publishCard(relay, a, { now: t })).statusCode).toBe(200);
    expect((await publishCard(relay, a, { now: t, contact: 'open' })).json().error).toBe('stale_descriptor');
  });

  it('equal identical is idempotent', async () => {
    const a = await registered(relay);
    const bundle = await cardOf(a, { handle: 'idem-alice' });
    expect((await postCard(relay, bundle)).json()).toEqual({ ok: true });
    expect((await postCard(relay, bundle)).json()).toEqual({ ok: true });
    expect((await get(`/v1/card/${a.aceId}`)).json()).toEqual(bundle);
  });
});

describe('handles', () => {
  it('handle resolves to card bundle', async () => {
    const a = await registered(relay);
    const bundle = await cardOf(a, { handle: 'alice' });
    expect((await postCard(relay, bundle)).statusCode).toBe(200);
    const res = await get('/v1/handles/alice');
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual(bundle);
    expect(res.json().card.handle).toBe('alice');
    expect((await get('/v1/handles/nobody-here')).json().error).toBe('unknown_peer');
    expect((await get('/v1/handles/X')).json().error).toBe('unknown_peer');
  });

  it('handle is claimed only at home', async () => {
    const a = await registered(relay), b = await registered(relay);
    expect((await publishCard(relay, a, { home: OTHER_HOME, handle: 'roamer' })).statusCode).toBe(200);
    expect((await get('/v1/handles/roamer')).json().error).toBe('unknown_peer');
    expect((await get(`/v1/card/${a.aceId}`)).json().card.home).toBe(OTHER_HOME);
    // Nothing was bound here: another identity can claim it.
    expect((await publishCard(relay, b, { handle: 'roamer' })).statusCode).toBe(200);
    expect((await get('/v1/handles/roamer')).json().card.aceId).toBe(b.aceId);
  });

  it('handle_taken for another identity', async () => {
    const a = await registered(relay), b = await registered(relay);
    expect((await publishCard(relay, a, { handle: 'taken' })).statusCode).toBe(200);
    expect((await publishCard(relay, b, { handle: 'taken' })).json().error).toBe('handle_taken');
    expect((await get('/v1/handles/taken')).json().card.aceId).toBe(a.aceId);
    expect(await relay.redis.ttl('ace:handle:taken')).toBe(-1);
  });

  it('second handle is refused', async () => {
    const a = await registered(relay);
    expect((await publishCard(relay, a, { handle: 'second' })).statusCode).toBe(200);
    expect((await publishCard(relay, a, { handle: 'second2', now: now() + 1 })).json().error).toBe('invalid_argument');
    expect((await get('/v1/handles/second')).json().card.aceId).toBe(a.aceId);
    expect((await get('/v1/handles/second2')).json().error).toBe('unknown_peer');
    expect(await relay.redis.exists('ace:handle:second2')).toBe(0);
  });

  it('dropping the handle is refused', async () => {
    const a = await registered(relay);
    expect((await publishCard(relay, a, { handle: 'keeper' })).statusCode).toBe(200);
    expect((await publishCard(relay, a, { now: now() + 1 })).json().error).toBe('invalid_argument');
    expect((await get('/v1/handles/keeper')).json().card.handle).toBe('keeper');
  });

  it('foreign home is accepted and claims nothing', async () => {
    const a = await registered(relay), b = await registered(relay);
    expect((await publishCard(relay, a, { handle: 'mover' })).statusCode).toBe(200);
    // Another home: accepted, claims nothing here, the binding here stays.
    expect((await publishCard(relay, a, { home: OTHER_HOME, handle: 'elsewhere', now: now() + 1 })).statusCode).toBe(200);
    expect((await get('/v1/handles/mover')).json().error).toBe('unknown_peer');
    expect((await get('/v1/handles/elsewhere')).json().error).toBe('unknown_peer');
    expect(await relay.redis.get('ace:handle:mover')).toBe(a.aceId);
    expect(await relay.redis.exists('ace:handle:elsewhere')).toBe(0);
    expect((await publishCard(relay, b, { handle: 'mover', now: now() + 1 })).json().error).toBe('handle_taken');
    // Back home: only the bound handle.
    expect((await publishCard(relay, a, { handle: 'other', now: now() + 2 })).json().error).toBe('invalid_argument');
    expect((await publishCard(relay, a, { handle: 'mover', now: now() + 2 })).statusCode).toBe(200);
    expect((await get('/v1/handles/mover')).json().card.aceId).toBe(a.aceId);
  });

  it('card goes dark after rotation until re-signed', async () => {
    const a = await published(relay, { contact: 'open', listed: true, handle: 'rotor' });
    const from = await newAgent();
    const inDirectory = async () => {
      const ids: string[] = [];
      for (let cursor: string | null = null; ;) {
        const page = (await get(`/v1/descriptors?limit=100${cursor ? `&cursor=${cursor}` : ''}`)).json();
        ids.push(...page.agents.map((x: any) => x.descriptor.aceId));
        if (!(cursor = page.cursor)) return ids.includes(a.aceId);
      }
    };
    expect(await inDirectory()).toBe(true);
    await a.id.delegate();
    expect((await register(relay, a, now() + 1)).json().status).toBe('rotated');
    // A fresh descriptor under the new KEL: only the stale card stands between a stranger and the recipient now.
    expect((await publish(relay, a, { now: now() + 1 })).statusCode).toBe(200);
    expect((await send(relay, await packet(from, a))).json()).toEqual({ error: 'not_permitted', message: 'not permitted' });
    expect((await get(`/v1/card/${a.aceId}`)).json().error).toBe('unknown_peer');
    expect((await get('/v1/handles/rotor')).json().error).toBe('unknown_peer');
    expect(await inDirectory()).toBe(false);
    // Re-signed under the new KEL (set once still applies): everything is back, same handle.
    expect((await publishCard(relay, a, { contact: 'open', listed: true, now: now() + 2 })).json().error).toBe('invalid_argument');
    expect((await publishCard(relay, a, { contact: 'open', listed: true, handle: 'rotor', now: now() + 2 })).statusCode).toBe(200);
    expect((await get(`/v1/card/${a.aceId}`)).json().kel).toEqual(a.id.getKel());
    expect((await get('/v1/handles/rotor')).json().card.aceId).toBe(a.aceId);
    expect(await inDirectory()).toBe(true);
    expect((await send(relay, await packet(from, a))).json()).toEqual({ ok: true });
    // Leave the directory to the directory test.
    expect((await publishCard(relay, a, { handle: 'rotor', now: now() + 3 })).statusCode).toBe(200);
  });

  it('handle stays bound while card is dark', async () => {
    const a = await registered(relay), b = await registered(relay);
    expect((await publishCard(relay, a, { handle: 'dark' })).statusCode).toBe(200);
    await a.id.delegate();
    expect((await register(relay, a, now() + 1)).json().status).toBe('rotated');
    expect((await get('/v1/handles/dark')).json().error).toBe('unknown_peer');
    expect((await publishCard(relay, b, { handle: 'dark' })).json().error).toBe('handle_taken');
    expect(await relay.redis.get('ace:handle:dark')).toBe(a.aceId);
  });

  it('concurrent claims: exactly one wins', async () => {
    const a = await registered(relay), b = await registered(relay);
    const [ca, cb] = await Promise.all([cardOf(a, { handle: 'race' }), cardOf(b, { handle: 'race' })]);
    const codes = (await Promise.all([postCard(relay, ca), postCard(relay, cb)])).map((r) => r.statusCode).sort();
    expect(codes).toEqual([200, 409]);
  });

  it('claim rate limit per network', async () => {
    // The relay default (8 a day per client network) on a second instance over the same db.
    const limited = await createTestRelay(14, { handleClaimsPerNetworkPerDay: 8 }, { flush: false });
    try {
      const agents = await Promise.all(Array.from({ length: 10 }, () => registered(limited)));
      for (let i = 0; i < 8; i++) expect((await publishCard(limited, agents[i], { handle: `claim-${i}` }, '203.0.113.9')).statusCode).toBe(200);
      // An unchanged handle is no new claim.
      expect((await publishCard(limited, agents[0], { handle: 'claim-0', now: now() + 1 }, '203.0.113.9')).statusCode).toBe(200);
      // Nor is a record without one.
      expect((await publishCard(limited, agents[9], {}, '203.0.113.10')).statusCode).toBe(200);
      const refused = await publishCard(limited, agents[8], { handle: 'claim-8' }, '203.0.113.11');
      expect(refused.statusCode).toBe(429);
      expect(refused.json().error).toBe('rate_limited');
      expect(Number(refused.headers['retry-after'])).toBeGreaterThan(0);
      expect(await limited.redis.exists('ace:handle:claim-8')).toBe(0);
      expect((await get(`/v1/card/${agents[8].aceId}`)).json().error).toBe('unknown_peer');
      // Another network still claims.
      expect((await publishCard(limited, agents[8], { handle: 'claim-8' }, '198.51.100.9')).statusCode).toBe(200);
    } finally {
      await limited.close();
    }
  });

  it('unregister keeps the handle bound', async () => {
    const a = await registered(relay), b = await registered(relay);
    expect((await publishCard(relay, a, { handle: 'leaver' })).statusCode).toBe(200);
    expect((await unregister(a)).statusCode).toBe(200);
    expect((await get('/v1/handles/leaver')).json().error).toBe('unknown_peer');
    expect((await get(`/v1/card/${a.aceId}`)).json().error).toBe('unknown_peer');
    expect(await relay.redis.hget(`ace:card:${a.aceId}`, 'json')).toBeNull();
    expect(await relay.redis.get('ace:handle:leaver')).toBe(a.aceId);
    expect(await relay.redis.ttl('ace:handle:leaver')).toBe(-1);
    expect((await publishCard(relay, b, { handle: 'leaver' })).json().error).toBe('handle_taken');
    // Re-registered, the identity still holds exactly that handle.
    expect((await register(relay, a, now() + 2)).statusCode).toBe(200);
    expect((await publishCard(relay, a, { now: now() + 3 })).json().error).toBe('invalid_argument');
    expect((await publishCard(relay, a, { handle: 'leaver', now: now() + 3 })).statusCode).toBe(200);
    expect((await get('/v1/handles/leaver')).json().card.aceId).toBe(a.aceId);
  });

  it('a deleted record cannot be replayed over a newer one', async () => {
    const a = await registered(relay);
    const t = now();
    const older = await cardOf(a, { now: t });
    expect((await postCard(relay, older)).statusCode).toBe(200);
    const newer = await cardOf(a, { now: t + 1, contact: 'open' });
    expect((await postCard(relay, newer)).statusCode).toBe(200);
    expect((await unregister(a, t + 2)).statusCode).toBe(200);
    expect((await register(relay, a, t + 3)).statusCode).toBe(200);
    expect((await postCard(relay, older)).json().error).toBe('stale_descriptor');
    expect((await postCard(relay, newer)).statusCode).toBe(200);
    expect(await relay.redis.hget(`ace:card:${a.aceId}`, 'digest')).toBe(documentDigest(newer.card));
  });
});

describe('lookups and directory', () => {
  it('descriptor is public regardless', async () => {
    const a = await published(relay);
    expect((await get(`/v1/descriptor/${a.aceId}`)).json().descriptor.aceId).toBe(a.aceId);
    const closed = await published(relay, { contact: 'closed', listed: false });
    expect((await get(`/v1/descriptor/${closed.aceId}`)).statusCode).toBe(200);
    expect((await get('/v1/descriptor/not-an-id')).statusCode).toBe(404);
    await relay.redis.hset(`ace:descriptor:${a.aceId}`, 'expiresAt', String(now() - 1));
    expect((await get(`/v1/descriptor/${a.aceId}`)).json().error).toBe('unknown_peer');
  });

  it('resolve route is gone', async () => {
    const res = await relay.app.inject({ method: 'POST', url: '/v1/descriptor/resolve', payload: { aceId: 'x', permit: {} } });
    expect(res.statusCode).toBe(404);
    expect(res.json()).toEqual({ error: 'not_found' });
  });

  it('directory lists only listed', async () => {
    // Earlier tests in this suite list nobody; a listed identity without a descriptor is not listed either.
    const agents: string[] = [];
    for (let i = 0; i < 6; i++) {
      const a = await published(relay, { listed: i < 4 || i === 5, contact: 'closed' });
      if (i < 4) agents.push(a.aceId);
      if (i === 5) await relay.redis.hset(`ace:descriptor:${a.aceId}`, 'expiresAt', String(now() - 1));
    }
    const noDescriptor = await registered(relay);
    expect((await publishCard(relay, noDescriptor, { listed: true })).statusCode).toBe(200);
    agents.sort();
    const page1 = (await get('/v1/descriptors?limit=3')).json();
    expect(page1.agents.map((x: any) => x.descriptor.aceId)).toEqual(agents.slice(0, 3));
    expect(page1.cursor).toBe(agents[2]);
    const page2 = (await get(`/v1/descriptors?limit=3&cursor=${page1.cursor}`)).json();
    expect(page2.agents.map((x: any) => x.descriptor.aceId)).toEqual(agents.slice(3));
    expect(page2.cursor).toBeNull();
    expect((await get('/v1/descriptors?profile=ace:text:1')).json().agents).toHaveLength(4);
    expect((await get('/v1/descriptors?profile=ace:commerce:1')).json()).toEqual({ agents: [], cursor: null });
    expect((await get('/v1/descriptors?limit=0')).json().error).toBe('invalid_argument');
    expect((await get('/v1/descriptors?cursor=x')).json().error).toBe('invalid_argument');
    // Unlisting removes the entry.
    const [first] = agents;
    const self = (await get(`/v1/card/${first}`)).json() as CardBundle;
    expect(self.card.listed).toBe(true);
    expect(await relay.redis.zscore('ace:descriptors', first)).not.toBeNull();
  });

  it('unlisting and unregister leave the directory', async () => {
    const a = await published(relay, { listed: true });
    expect(await relay.redis.zscore('ace:descriptors', a.aceId)).not.toBeNull();
    expect((await publishCard(relay, a, { listed: false, now: now() + 1 })).statusCode).toBe(200);
    expect(await relay.redis.zscore('ace:descriptors', a.aceId)).toBeNull();
    expect((await publishCard(relay, a, { listed: true, now: now() + 2 })).statusCode).toBe(200);
    expect((await unregister(a, now() + 3)).statusCode).toBe(200);
    expect(await relay.redis.zscore('ace:descriptors', a.aceId)).toBeNull();
  });
});

describe('send without a permit', () => {
  it('stranger send needs open card', async () => {
    const from = await newAgent();
    const none = await published(relay);
    const closed = await published(relay, { contact: 'closed' });
    const open = await published(relay, { contact: 'open' });
    const openNoDescriptor = await registered(relay);
    expect((await publishCard(relay, openNoDescriptor, { contact: 'open' })).statusCode).toBe(200);
    for (const to of [none, closed]) {
      expect((await send(relay, await packet(from, to))).json()).toEqual({ error: 'not_permitted', message: 'not permitted' });
    }
    expect((await send(relay, await packet(from, open))).json()).toEqual({ ok: true });
    // The packet is addressed with a prekey from the agent's vault; the relay needs an unexpired descriptor too.
    await publish(relay, openNoDescriptor);
    await relay.redis.hset(`ace:descriptor:${openNoDescriptor.aceId}`, 'expiresAt', String(now() - 1));
    expect((await send(relay, await packet(from, openNoDescriptor))).json().error).toBe('not_permitted');
  });
});
