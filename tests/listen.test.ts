import { connect, type Socket } from 'node:net';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { SSE_MAX_BUFFERED_BYTES } from '../src/config.js';
import {
  authHeaders, createReplica, createTestRelay, endListenAfterCatchup, inbox, sseEvents, newAgent, now, packet, permit, published, register, registered, send,
  type Agent, type TestRelay,
} from './helpers.js';

let relay: TestRelay;
let base: string;
beforeAll(async () => {
  relay = await createTestRelay(5, { ssePerIdentity: 1, globalSseLimit: 3 });
  await relay.app.listen({ host: '127.0.0.1', port: 0 });
  const addr = relay.app.server.address() as { port: number };
  base = `http://127.0.0.1:${addr.port}`;
});
afterAll(async () => { await relay.close(); });

async function open(agent: Agent, since = '-', signal?: AbortSignal): Promise<Response> {
  const headers = await authHeaders(agent, { action: 'listen', since });
  return fetch(`${base}/v1/listen${since === '-' ? '' : `?since=${since}`}`, { headers, signal });
}

describe('GET /v1/listen', () => {
  it('sends connected, then catchup after since; listening does not delete', async () => {
    const to = await published(relay), from = await newAgent();
    const p = await permit(to, from);
    const packets = [await packet(from, to, { message: 'a' }), await packet(from, to, { message: 'b' })];
    for (const pk of packets) await send(relay, pk, p);
    const spy = endListenAfterCatchup(relay);
    try {
      const res = await relay.app.inject({ method: 'GET', url: '/v1/listen', headers: await authHeaders(to, { action: 'listen', since: '-' }) });
      expect(res.headers['content-type']).toBe('text/event-stream');
      const frames = res.body.split('\n\n').filter(Boolean);
      expect(frames[0]).toBe(`event: connected\ndata: ${JSON.stringify({ aceId: to.aceId })}`);
      const events = frames.slice(1).map((f) => Object.fromEntries(f.split('\n').map((l) => [l.slice(0, l.indexOf(':')), l.slice(l.indexOf(':') + 2)])));
      expect(events.map((e) => e.event)).toEqual(['catchup', 'catchup']);
      expect(events.map((e) => JSON.parse(e.data))).toEqual(packets.map((pk) => ({ packet: pk })));
      const after = await relay.app.inject({ method: 'GET', url: `/v1/listen?since=${events[0].id}`, headers: await authHeaders(to, { action: 'listen', since: events[0].id }) });
      expect(after.body.split('\n\n').filter((f) => f.includes('event: catchup'))).toHaveLength(1);
    } finally {
      spy.mockRestore();
    }
    expect((await inbox(relay, to)).json().messages).toHaveLength(2);
  });

  it('pushes new packets live as message events', async () => {
    const to = await published(relay), from = await newAgent();
    const ctl = new AbortController();
    const res = await open(to, '-', ctl.signal);
    expect(res.status).toBe(200);
    const events = sseEvents(res.body!);
    expect((await events.next()).value).toMatchObject({ event: 'connected' });
    const pk = await packet(from, to);
    await send(relay, pk, await permit(to, from));
    const ev = (await events.next()).value!;
    expect(ev.event).toBe('message');
    expect(JSON.parse(ev.data)).toEqual({ packet: pk });
    ctl.abort();
  });

  it('delivers a packet queued while the notify subscription was down once it is back', async () => {
    const to = await published(relay), from = await newAgent();
    const ctl = new AbortController();
    const sub = relay.subscriberRedis;
    const retry = sub.options.retryStrategy;
    try {
      const res = await open(to, '-', ctl.signal);
      const events = sseEvents(res.body!);
      expect((await events.next()).value).toMatchObject({ event: 'connected' });
      await vi.waitFor(async () => expect(await relay.sseRegistry.listening(to.aceId)).toBe(true));
      sub.options.retryStrategy = () => 300; // the send below lands while it is down
      sub.disconnect(true);
      await vi.waitFor(() => expect(sub.status).not.toBe('ready'));
      const pk = await packet(from, to);
      expect((await send(relay, pk, await permit(to, from))).statusCode).toBe(200);
      const next = await Promise.race([events.next(), new Promise<'timeout'>((r) => setTimeout(() => r('timeout'), 5000))]);
      expect(next).not.toBe('timeout');
      const ev = (next as IteratorResult<{ event?: string; data: string }>).value!;
      expect(ev.event).toBe('message');
      expect(JSON.parse(ev.data)).toEqual({ packet: pk });
    } finally {
      sub.options.retryStrategy = retry;
      ctl.abort();
    }
  }, 15_000);

  it('bounds streams per identity and globally, never per IP; unregister closes them', async () => {
    const agents = [await registered(relay), await registered(relay), await registered(relay), await registered(relay)];
    const ctl = new AbortController();
    try {
      const first = await open(agents[0], '-', ctl.signal);
      expect(first.status).toBe(200);
      const second = await open(agents[0]);
      expect(second.status).toBe(429);
      expect(await second.json()).toMatchObject({ error: 'rate_limited' });
      // Same client address, other identities: admitted up to the global bound.
      expect((await open(agents[1], '-', ctl.signal)).status).toBe(200);
      expect((await open(agents[2], '-', ctl.signal)).status).toBe(200);
      expect((await open(agents[3])).status).toBe(429);
      expect(relay.sseRegistry.getStats()).toEqual({ connections: 3 });

      const closed = (async () => { for await (const _ of sseEvents(first.body!)) { /* drain */ } })();
      const res = await relay.app.inject({ method: 'POST', url: '/v1/unregister', headers: await authHeaders(agents[0], { action: 'unregister' }, now() + 1) });
      expect(res.statusCode).toBe(200);
      await closed;
      await vi.waitFor(async () => expect(await relay.sseRegistry.listening(agents[0].aceId)).toBe(false));
    } finally {
      ctl.abort();
    }
  });
});

// Pub/sub is server-wide: a relay on another db of the same server (another environment) neither wakes nor counts it.
describe('GET /v1/listen notify channels', () => {
  it('are scoped to the db', async () => {
    const other = await createTestRelay(4, {}, { flush: false }); // the inbox suite's db: this relay only publishes
    const to = await registered(relay);
    const ctl = new AbortController();
    try {
      expect((await open(to, '-', ctl.signal)).status).toBe(200);
      await vi.waitFor(async () => expect(await relay.sseRegistry.listening(to.aceId)).toBe(true));
      expect(await other.sseRegistry.listening(to.aceId)).toBe(false);
      expect(await other.sseRegistry.notify(to.aceId)).toBe(0);
    } finally {
      ctl.abort();
      await other.close();
    }
  });
});

// Replicas share one Redis: unregister and re-registration revoke streams everywhere.
describe('GET /v1/listen across replicas', () => {
  let replica: TestRelay;
  beforeAll(async () => { replica = await createReplica(relay, 5); });
  afterAll(async () => { await replica.close(); });

  /** Every event after `connected` until the stream ends. */
  async function rest(res: Response): Promise<string[]> {
    const events = sseEvents(res.body!);
    expect((await events.next()).value).toMatchObject({ event: 'connected' });
    const seen: string[] = [];
    for await (const ev of events) seen.push(ev.event);
    return seen;
  }

  it('unregister on another replica closes the stream; after re-registration the old stream gets nothing', async () => {
    const to = await registered(relay), from = await newAgent();
    const res = await open(to);
    expect(res.status).toBe(200);
    const seen = rest(res);
    await vi.waitFor(async () => expect(await relay.sseRegistry.listening(to.aceId)).toBe(true));
    const un = await replica.app.inject({ method: 'POST', url: '/v1/unregister', headers: await authHeaders(to, { action: 'unregister' }, now() + 1) });
    expect(un.statusCode).toBe(200);
    expect(await seen).toEqual([]);
    await vi.waitFor(async () => expect(await relay.sseRegistry.listening(to.aceId)).toBe(false));

    expect((await register(replica, to, now() + 2)).statusCode).toBe(200);
    const pk = await packet(from, to);
    expect((await send(replica, pk, await permit(to, from))).statusCode).toBe(200);
    // Only a stream opened under the new registration receives it.
    const spy = endListenAfterCatchup(relay);
    try {
      const fresh = await relay.app.inject({ method: 'GET', url: '/v1/listen', headers: await authHeaders(to, { action: 'listen', since: '-' }) });
      expect(fresh.body).toContain(pk.messageId);
    } finally {
      spy.mockRestore();
    }
  });

  it('closes a stream whose registration changed before writing, even without an eviction notice', async () => {
    const to = await registered(relay), from = await newAgent();
    const res = await open(to);
    expect(res.status).toBe(200);
    const seen = rest(res);
    await vi.waitFor(async () => expect(await relay.sseRegistry.listening(to.aceId)).toBe(true));
    // Re-registration publishes no notice; the next packet's wake-up finds the stream's registration stale.
    expect((await register(replica, to, now() + 1)).json()).toMatchObject({ status: 'refreshed' });
    expect((await send(replica, await packet(from, to), await permit(to, from))).statusCode).toBe(200);
    expect(await seen).toEqual([]);
    await vi.waitFor(async () => expect(await relay.sseRegistry.listening(to.aceId)).toBe(false));
  });
});

// A closed slow consumer keeps its slot until the socket is gone, and its socket and buffers are released.
// Runs last: it rebuilds db 5.
describe('GET /v1/listen backpressure', () => {
  it('delivers a packet larger than the socket buffer to a reading client', async () => {
    const to = await published(relay), from = await newAgent();
    const big = await packet(from, to, { message: 'z'.repeat(1_100_000) });
    expect((await send(relay, big, await permit(to, from))).statusCode).toBe(200);
    const ac = new AbortController();
    const res = await open(to, '-', ac.signal);
    expect(res.status).toBe(200);
    const reader = res.body!.getReader();
    let text = '';
    while (!text.includes('event: catchup')) {
      const { value, done } = await reader.read();
      if (done) break;
      text += new TextDecoder().decode(value);
    }
    while (!/event: catchup\ndata: .*\n\n/s.test(text)) {
      const { value, done } = await reader.read();
      if (done) break;
      text += new TextDecoder().decode(value);
    }
    expect(text).toContain(big.messageId);
    ac.abort();
  }, 30_000);

  it('destroys a zero-window stream, holds its slot until the socket closes, and bounds its buffer', async () => {
    const r = await createTestRelay(5, { ssePerIdentity: 1, sseWriteTimeoutMs: 500 });
    try {
      await r.app.listen({ host: '127.0.0.1', port: 0 });
      const port = (r.app.server.address() as { port: number }).port;
      const serverSockets: Socket[] = [];
      r.app.server.on('connection', (c: Socket) => serverSockets.push(c));
      const victim = await registered(r), sender = await newAgent();
      const p = await permit(victim, sender);
      for (let i = 0; i < 2; i++) expect((await send(r, await packet(sender, victim, { message: 'x'.repeat(1_100_000) }), p)).statusCode).toBe(200);

      const stuck = async (): Promise<Socket> => {
        const h = await authHeaders(victim, { action: 'listen', since: '-' });
        const s = connect({ host: '127.0.0.1', port });
        s.on('error', () => {});
        await new Promise((res) => s.once('connect', res));
        s.pause(); // never reads
        s.write(`GET /v1/listen HTTP/1.1\r\nHost: x\r\n${Object.entries(h).map(([k, v]) => `${k}: ${v}`).join('\r\n')}\r\n\r\n`);
        return s;
      };
      const first = await stuck();
      await vi.waitFor(() => expect(serverSockets.some((c) => c.writableLength > 0)).toBe(true), { timeout: 8000 });
      // The paused client never sees 'close'; watch the server side of its connection.
      const held = serverSockets.find((c) => c.writableLength > 0)!;
      expect(held).toBeDefined();
      const closed = new Promise((res) => held.once('close', res));
      expect(r.sseRegistry.getStats().connections).toBe(1);
      // Buffered output stays within one frame, not the whole backlog.
      const buffered = serverSockets.reduce((n, c) => n + c.writableLength, 0);
      expect(buffered).toBeLessThanOrEqual(SSE_MAX_BUFFERED_BYTES);
      // The slot is still held: a second stream is refused while the first socket exists.
      const refused = await open2(port, victim);
      expect(refused).toBe(429);
      // The drain timeout destroys the socket; only then is the slot released.
      await closed;
      await vi.waitFor(() => expect(r.sseRegistry.getStats().connections).toBe(0));
      expect(held.destroyed).toBe(true);
      first.destroy();
    } finally {
      await r.close();
    }
  }, 30_000);

  it('bounds the bytes all streams buffer together; shutdown ends them and refuses new ones', async () => {
    const r = await createTestRelay(5, { ssePerIdentity: 1, sseBufferBytes: SSE_MAX_BUFFERED_BYTES }, { flush: false });
    try {
      await r.app.listen({ host: '127.0.0.1', port: 0 });
      const port = (r.app.server.address() as { port: number }).port;
      const serverSockets: Socket[] = [];
      r.app.server.on('connection', (c: Socket) => serverSockets.push(c));
      const sender = await newAgent();
      const [a, b] = [await registered(r), await registered(r)];
      // a's backlog (~7 MB) exceeds what the kernel's socket buffers absorb, so part of it stays buffered here.
      for (const [v, frames] of [[a, 6], [b, 2]] as const) {
        for (let i = 0; i < frames; i++) expect((await send(r, await packet(sender, v, { message: 'x'.repeat(1_100_000) }), await permit(v, sender))).statusCode).toBe(200);
      }
      const sockets = [await stuckListen(port, a)];
      // a's backlog is stuck in the server side of its connection.
      await vi.waitFor(() => expect(serverSockets[0]?.writableLength).toBeGreaterThan(0), { timeout: 8000 });
      // b's frame would take all streams past the budget: once its stream opened (headers written, slot counted), it is
      // ended and its slot released; a's is kept.
      sockets.push(await stuckListen(port, b));
      await vi.waitFor(() => expect(serverSockets[1]?.bytesWritten).toBeGreaterThan(0), { timeout: 8000 });
      await vi.waitFor(() => expect(r.sseRegistry.getStats().connections).toBe(1), { timeout: 8000 });
      expect(serverSockets[0].destroyed).toBe(false);
      r.sseRegistry.drain();
      expect(await open2(port, b)).toBe(429);
      await vi.waitFor(() => expect(r.sseRegistry.getStats().connections).toBe(0), { timeout: 8000 });
      for (const s of sockets) s.destroy();
    } finally {
      await r.close();
    }
  }, 30_000);
});

/** A listen stream whose client never reads. */
async function stuckListen(port: number, agent: Agent): Promise<Socket> {
  const h = await authHeaders(agent, { action: 'listen', since: '-' });
  const s = connect({ host: '127.0.0.1', port });
  s.on('error', () => {});
  await new Promise((res) => s.once('connect', res));
  s.pause();
  s.write(`GET /v1/listen HTTP/1.1\r\nHost: x\r\n${Object.entries(h).map(([k, v]) => `${k}: ${v}`).join('\r\n')}\r\n\r\n`);
  return s;
}

async function open2(port: number, agent: Agent): Promise<number> {
  const headers = await authHeaders(agent, { action: 'listen', since: '-' });
  const ac = new AbortController();
  const res = await fetch(`http://127.0.0.1:${port}/v1/listen`, { headers, signal: ac.signal });
  ac.abort();
  return res.status;
}
