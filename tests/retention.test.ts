import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestRelay, inbox, newAgent, packet, permit, published, send, type TestRelay } from './helpers.js';

let relay: TestRelay;
beforeAll(async () => { relay = await createTestRelay(12, { messageTtlSeconds: 86_400 }); });
afterAll(async () => { await relay.close(); });

describe('retention', () => {
  it('stranger entries expire after 86,400 s and free the allowance', async () => {
    const to = await published(relay, { visibility: 'public' }), s = await newAgent();
    expect((await send(relay, await packet(s, to))).statusCode).toBe(200);
    const [id, score] = await relay.redis.zrange(`ace:inbox-strangers:${to.aceId}`, 0, -1, 'WITHSCORES');
    expect(Number(score) - Number(id.split('-')[0])).toBe(86_400_000);
    await relay.redis.zadd(`ace:inbox-strangers:${to.aceId}`, Date.now() - 1, id); // as if a day had passed
    expect((await inbox(relay, to)).json().messages).toEqual([]);
    expect(await relay.redis.hgetall(`ace:inbox-meta:${to.aceId}`)).toMatchObject({ sn: '0' });
    expect(await relay.redis.hlen(`ace:inbox-dedup:${to.aceId}`)).toBe(0);
  });

  it('normal entries expire after MESSAGE_TTL_SECONDS; counters follow', async () => {
    const to = await published(relay), from = await newAgent();
    const p = await packet(from, to);
    // An entry written a day and a second ago, as the enqueue script would have written it.
    const json = JSON.stringify(p);
    const old = `${Date.now() - 86_401_000}-0`;
    await relay.redis.xadd(`ace:inbox:${to.aceId}`, old, 'json', json, 'n', String(json.length), 'k', 'n', 'd', 'f'.repeat(64));
    await relay.redis.hset(`ace:inbox-meta:${to.aceId}`, 'nn', '1', 'nb', String(json.length));
    await relay.redis.hset(`ace:inbox-dedup:${to.aceId}`, 'f'.repeat(64), old);
    expect((await inbox(relay, to)).json().messages).toEqual([]);
    expect((await send(relay, await packet(from, to), await permit(to, from))).statusCode).toBe(200);
    expect(await relay.redis.xlen(`ace:inbox:${to.aceId}`)).toBe(1);
    expect(await relay.redis.hget(`ace:inbox-meta:${to.aceId}`, 'nn')).toBe('1');
    expect(await relay.redis.hlen(`ace:inbox-dedup:${to.aceId}`)).toBe(1);
    expect(await relay.redis.ttl(`ace:inbox:${to.aceId}`)).toBeGreaterThan(86_000);
  });
});
