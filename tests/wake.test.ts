import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { OFFLINE_WINDOW_SECONDS } from '@ace-protocol/sdk';
import { WAKE_BYTES } from '../src/store/wake.js';
import {
  authHeaders, createTestRelay, deleteWake, inbox, newAgent, now, packet, permit, published, putWake, register, send, testConfig, wakeOf,
  type TestRelay,
} from './helpers.js';

const GATEWAY = 'https://push.example/ace';
const token = (n: number) => `tok${String(n).padStart(19, '0')}`;

/** A gateway behind the relay's wake fetch: records each request; `answer` sets the response (default 204). */
function gatewayMock() {
  const calls: Array<{ url: string; body: { token: string } }> = [];
  let answer: () => Promise<Response> = async () => new Response(null, { status: 204 });
  const fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(input), body: JSON.parse(String(init?.body)) });
    return answer();
  }) as typeof globalThis.fetch;
  return {
    calls, fetch,
    callsFor: (tok: string) => calls.filter((c) => c.body.token === tok),
    answer: (f: () => Promise<Response>) => { answer = f; },
  };
}

let relay: TestRelay;
const gw = gatewayMock();
beforeAll(async () => {
  relay = await createTestRelay(0, { wakeGateways: [GATEWAY, 'https://other.example'], wakeMinIntervalSeconds: 0 }, { wakeFetch: gw.fetch });
});
afterAll(async () => { await relay.close(); });

const settle = () => new Promise((r) => setTimeout(r, 50));

/** A published recipient of `r` with a wake registration, a sender and its permit. */
async function setup(tok: string, r = relay) {
  const to = await published(r), from = await newAgent();
  expect((await putWake(r, to, GATEWAY, tok)).statusCode).toBe(200);
  return { to, from, p: await permit(to, from) };
}

describe('PUT / DELETE /v1/wake', () => {
  it('stores, replaces and removes one registration per identity, charged once', async () => {
    const a = await published(relay);
    const rn = await relay.redis.hget(`ace:identity:${a.aceId}`, 'regnet');
    const stored = async () => Number(await relay.redis.get(`ace:regnet-stored:${rn}`) ?? 0);
    const before = await stored();
    expect((await putWake(relay, a, GATEWAY, token(1))).json()).toEqual({ ok: true });
    expect(await wakeOf(relay, a.aceId)).toEqual({ gateway: GATEWAY, token: token(1), armed: true });
    expect(await stored()).toBe(before + WAKE_BYTES);
    expect((await putWake(relay, a, 'https://other.example', token(2))).statusCode).toBe(200);
    expect(await wakeOf(relay, a.aceId)).toMatchObject({ gateway: 'https://other.example', token: token(2) });
    expect(await stored()).toBe(before + WAKE_BYTES);
    expect(await relay.redis.ttl(`ace:wake:${a.aceId}`)).toBeGreaterThan(OFFLINE_WINDOW_SECONDS - 10);
    expect((await deleteWake(relay, a)).json()).toEqual({ ok: true });
    expect((await deleteWake(relay, a)).statusCode).toBe(200); // idempotent
    expect(await wakeOf(relay, a.aceId)).toBeNull();
    expect(await stored()).toBe(before);
  });

  it('refuses malformed and unlisted gateways and tokens with invalid_argument, before authentication', async () => {
    const a = await published(relay);
    for (const [gateway, tok] of [
      ['https://unlisted.example', token(1)], ['http://push.example/ace', token(1)], [`${GATEWAY}/`, token(1)], [GATEWAY, 'short'],
      [GATEWAY, `${token(1)}=`], [GATEWAY, 'x'.repeat(513)],
    ]) {
      const res = await relay.app.inject({ method: 'PUT', url: '/v1/wake', payload: { gateway, token: tok }, headers: { 'content-type': 'application/json' } });
      expect([res.statusCode, res.json().error], `${gateway} ${tok}`).toEqual([400, 'invalid_argument']);
    }
    const extra = await relay.app.inject({ method: 'PUT', url: '/v1/wake', payload: { gateway: GATEWAY, token: token(1), aceId: a.aceId } });
    expect(extra.json().error).toBe('invalid_argument');
  });

  it('verifies the signature over gateway and token, and requires a registration', async () => {
    const a = await published(relay);
    const res = await relay.app.inject({
      method: 'PUT', url: '/v1/wake', payload: { gateway: GATEWAY, token: token(1) },
      headers: await authHeaders(a, { action: 'wake', gateway: GATEWAY, token: token(9) }),
    });
    expect([res.statusCode, res.json().error]).toEqual([401, 'invalid_signature']);
    expect((await putWake(relay, await newAgent(), GATEWAY, token(1))).json().error).toBe('not_registered');
  });

  it('is 404 not_found on a relay without wake hints', async () => {
    const off = await createTestRelay(0, {}, { flush: false });
    try {
      const a = await newAgent();
      await register(off, a);
      const put = await putWake(off, a, GATEWAY, token(1));
      expect([put.statusCode, put.json().error]).toEqual([404, 'not_found']);
      expect((await deleteWake(off, a)).statusCode).toBe(404);
    } finally {
      await off.close();
    }
  });
});

describe('wakes', () => {
  it('one wake per armed period: disarmed by the wake, re-armed by inbox / inbox-ack', async () => {
    const { to, from, p } = await setup(token(3));
    expect((await send(relay, await packet(from, to, { message: '1' }), p)).statusCode).toBe(200);
    await vi.waitFor(() => expect(gw.callsFor(token(3))).toHaveLength(1));
    expect(gw.callsFor(token(3))[0]).toEqual({ url: GATEWAY, body: { token: token(3) } });
    await send(relay, await packet(from, to, { message: '2' }), p);
    await settle();
    expect(gw.callsFor(token(3))).toHaveLength(1); // disarmed until the endpoint fetches
    expect((await inbox(relay, to)).statusCode).toBe(200);
    await send(relay, await packet(from, to, { message: '3' }), p);
    await vi.waitFor(() => expect(gw.callsFor(token(3))).toHaveLength(2));
  });

  it('a duplicate packet queues nothing and wakes nothing', async () => {
    const { to, from, p } = await setup(token(4));
    const pk = await packet(from, to);
    await send(relay, pk, p);
    await vi.waitFor(() => expect(gw.callsFor(token(4))).toHaveLength(1));
    await inbox(relay, to);
    await send(relay, pk, p); // byte-identical: already queued
    await settle();
    expect(gw.callsFor(token(4))).toHaveLength(1);
  });

  it('a gateway that answers 404 or 410 loses the registration; 5xx is retried once and kept', async () => {
    for (const status of [404, 410]) {
      const { to, from, p } = await setup(token(10 + status));
      gw.answer(async () => new Response(null, { status }));
      await send(relay, await packet(from, to), p);
      await vi.waitFor(async () => expect(await wakeOf(relay, to.aceId)).toBeNull());
    }
    const { to, from, p } = await setup(token(5));
    gw.answer(async () => new Response(null, { status: 503 }));
    await send(relay, await packet(from, to), p);
    await vi.waitFor(() => expect(gw.callsFor(token(5))).toHaveLength(2), { timeout: 3000 });
    expect(await wakeOf(relay, to.aceId)).toMatchObject({ token: token(5), armed: false });
    gw.answer(async () => new Response(null, { status: 204 }));
  });

  it('unregister deletes the registration and its charge; a new registration has none', async () => {
    const { to } = await setup(token(6));
    const res = await relay.app.inject({ method: 'POST', url: '/v1/unregister', headers: await authHeaders(to, { action: 'unregister' }, now() + 1) });
    expect(res.statusCode).toBe(200);
    expect(await wakeOf(relay, to.aceId)).toBeNull();
    expect(await relay.redis.hget(`ace:identity:${to.aceId}`, 'wb')).toBeNull();
    expect((await register(relay, to, now() + 2)).json().status).toBe('registered');
    expect(await wakeOf(relay, to.aceId)).toBeNull();
  });

  it('a send answers the same, and as fast, whether or not the recipient registered a wake', async () => {
    const hung = gatewayMock();
    hung.answer(() => new Promise<Response>(() => undefined)); // the gateway never answers
    const r = await createTestRelay(0, { wakeGateways: [GATEWAY], wakeMinIntervalSeconds: 0 }, { flush: false, wakeFetch: hung.fetch });
    try {
      const { to: withWake, from, p } = await setup(token(7), r);
      const without = await published(r);
      const a = await send(r, await packet(from, withWake), p);
      const b = await send(r, await packet(from, without), await permit(without, from));
      const shape = (res: typeof a) => ({ status: res.statusCode, body: res.body, headers: Object.keys(res.headers).filter((h) => h !== 'date').sort() });
      expect(shape(a)).toEqual(shape(b));
      // The wake was started only after the response and is still pending: the send never waited for it.
      await vi.waitFor(() => expect(hung.calls).toHaveLength(1));
      expect(hung.calls[0].body).toEqual({ token: token(7) });
    } finally {
      await r.close();
    }
  });
});

describe('wakes and listen streams', () => {
  let live: TestRelay;
  let base: string;
  const lg = gatewayMock();
  beforeAll(async () => {
    live = await createTestRelay(0, { wakeGateways: [GATEWAY], wakeMinIntervalSeconds: 0 }, { flush: false, wakeFetch: lg.fetch });
    await live.app.listen({ host: '127.0.0.1', port: 0 });
    base = `http://127.0.0.1:${(live.app.server.address() as { port: number }).port}`;
  });
  afterAll(async () => { await live.close(); });

  it('no wake while a listen stream is open; the listen request re-armed it for afterwards', async () => {
    const { to, from, p } = await setup(token(8), live);
    await send(live, await packet(from, to, { message: 'wake' }), p);
    await vi.waitFor(() => expect(lg.calls).toHaveLength(1));
    const ctl = new AbortController();
    const res = await fetch(`${base}/v1/listen`, { headers: await authHeaders(to, { action: 'listen', since: '-' }), signal: ctl.signal });
    await res.body!.getReader().read(); // connected: subscribed
    expect((await wakeOf(live, to.aceId))!.armed).toBe(true);
    await send(live, await packet(from, to, { message: 'live' }), p);
    await settle();
    expect(lg.calls).toHaveLength(1);
    ctl.abort();
    await vi.waitFor(async () => expect(await live.sseRegistry.listening(to.aceId)).toBe(false));
    await send(live, await packet(from, to, { message: 'after' }), p);
    await vi.waitFor(() => expect(lg.calls).toHaveLength(2));
  });
});

describe('minimum interval', () => {
  it('defers a wake due within the interval instead of dropping it', async () => {
    const dg = gatewayMock();
    const r = await createTestRelay(0, { wakeGateways: [GATEWAY], wakeMinIntervalSeconds: 1 }, { flush: false, wakeFetch: dg.fetch });
    try {
      const { to, from, p } = await setup(token(11), r);
      await send(r, await packet(from, to, { message: '1' }), p);
      await vi.waitFor(() => expect(dg.calls).toHaveLength(1));
      const first = Date.now();
      await inbox(r, to);
      await send(r, await packet(from, to, { message: '2' }), p);
      await settle();
      expect(dg.calls).toHaveLength(1);
      await vi.waitFor(() => expect(dg.calls).toHaveLength(2), { timeout: 3000 });
      expect(Date.now() - first).toBeGreaterThanOrEqual(900);
    } finally {
      await r.close();
    }
  });
});

describe('config', () => {
  it('validates WAKE_GATEWAYS', () => {
    expect(() => testConfig({ wakeGateways: ['*', GATEWAY] })).toThrow(/stand alone/);
    expect(() => testConfig({ wakeGateways: ['http://push.example'] })).toThrow(/WAKE_GATEWAYS/);
    expect(() => testConfig({ wakeGateways: ['http://127.0.0.1:9999'] })).toThrow(/WAKE_GATEWAYS/);
    expect(testConfig({ wakeGateways: ['*'] }).wakeGateways).toEqual(['*']);
  });
});
