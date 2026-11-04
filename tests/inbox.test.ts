import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { MAX_INBOX_PAGE } from '@ace-protocol/sdk';
import { ack, authHeaders, createTestRelay, inbox, newAgent, packet, permit, published, send, type TestRelay } from './helpers.js';

let relay: TestRelay;
beforeAll(async () => { relay = await createTestRelay(4); });
afterAll(async () => { await relay.close(); });

describe('GET /v1/inbox and POST /v1/inbox/ack', () => {
  it('reads without deleting, pages with since/limit, and acks through a stream ID', async () => {
    const to = await published(relay), from = await newAgent();
    const p = await permit(to, from);
    const sent = [];
    for (let i = 0; i < 3; i++) {
      const pk = await packet(from, to, { message: `m${i}` });
      sent.push(pk);
      expect((await send(relay, pk, p)).statusCode).toBe(200);
    }
    const all = (await inbox(relay, to)).json();
    expect(all.messages.map((m: any) => m.packet)).toEqual(sent);
    expect(Object.keys(all.messages[0]).sort()).toEqual(['packet', 'streamId']);
    expect(all.cursor).toBe(all.messages[2].streamId);
    expect((await inbox(relay, to)).json().messages).toHaveLength(3); // non-destructive

    const first = (await inbox(relay, to, '-', 1)).json();
    expect(first.messages).toHaveLength(1);
    const rest = (await inbox(relay, to, first.cursor)).json();
    expect(rest.messages.map((m: any) => m.packet.messageId)).toEqual([sent[1].messageId, sent[2].messageId]);

    expect((await ack(relay, to, first.cursor)).json()).toEqual({ ok: true });
    expect((await ack(relay, to, first.cursor)).json()).toEqual({ ok: true }); // idempotent
    expect((await inbox(relay, to)).json().messages).toHaveLength(2);
    expect((await ack(relay, to, all.cursor)).statusCode).toBe(200);
    expect((await inbox(relay, to)).json()).toEqual({ messages: [], cursor: null });
    expect(await relay.redis.hgetall(`ace:inbox-meta:${to.aceId}`)).toMatchObject({ nn: '0', nb: '0' });
    expect(await relay.redis.hlen(`ace:inbox-dedup:${to.aceId}`)).toBe(0);
  });

  it('validates parameters', async () => {
    const to = await published(relay);
    const bad = await relay.app.inject({ method: 'GET', url: `/v1/inbox?limit=${MAX_INBOX_PAGE + 1}`, headers: await authHeaders(to, { action: 'inbox', since: '-', limit: 100 }) });
    expect(bad.json().error).toBe('invalid_argument');
    expect((await relay.app.inject({ method: 'POST', url: '/v1/inbox/ack', headers: await authHeaders(to, { action: 'inbox-ack', through: '1-0' }) })).json().error)
      .toBe('invalid_argument');
    expect((await relay.app.inject({ method: 'POST', url: '/v1/inbox/ack?through=-', headers: await authHeaders(to, { action: 'inbox-ack', through: '1-0' }) })).json().error)
      .toBe('invalid_argument');
    // The signature binds `through`.
    expect((await relay.app.inject({ method: 'POST', url: '/v1/inbox/ack?through=2-0', headers: await authHeaders(to, { action: 'inbox-ack', through: '1-0' }) })).json().error)
      .toBe('invalid_signature');
  });

  it('caps a page at MAX_PAGE_BYTES but returns at least one entry', async () => {
    const to = await published(relay), from = await newAgent();
    const p = await permit(to, from);
    const big = 'x'.repeat(1_100_000);
    for (let i = 0; i < 6; i++) expect((await send(relay, await packet(from, to, { message: big }), p)).statusCode).toBe(200);
    const page = (await inbox(relay, to)).json();
    expect(page.messages.length).toBeGreaterThan(0);
    expect(page.messages.length).toBeLessThan(6);
    const next = (await inbox(relay, to, page.cursor)).json();
    expect(page.messages.length + next.messages.length).toBe(6);
  });
});
