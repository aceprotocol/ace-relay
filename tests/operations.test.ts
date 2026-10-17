import Fastify from 'fastify';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config.js';
import { metricsRoutes } from '../src/routes/metrics.js';
import { createTestRelay, type TestRelay } from './helpers.js';

let relay: TestRelay;
beforeAll(async () => { relay = await createTestRelay(10); });
afterAll(async () => { await relay.close(); });

describe('operations', () => {
  it('GET /health checks Redis and its capacity', async () => {
    expect((await relay.app.inject({ method: 'GET', url: '/health' })).json()).toEqual({ ok: true });
  });

  it('GET /metrics (internal port) exports the listen-stream and used-bytes gauges only', async () => {
    const metrics = Fastify();
    await metrics.register(async (i) => metricsRoutes(i, { sseRegistry: relay.sseRegistry, storage: relay.storageMonitor }));
    const text = (await metrics.inject({ method: 'GET', url: '/metrics' })).body;
    expect(text.split('\n').filter((l) => l !== '' && !l.startsWith('#'))).toEqual([
      'ace_relay_sse_connections 0', expect.stringMatching(/^ace_relay_storage_used_bytes \d+$/),
    ]);
    await metrics.close();
  });

  it('a client address that is not an IP literal is invalid_argument, not a 500', async () => {
    const res = await relay.app.inject({ method: 'GET', url: '/v1/descriptors', remoteAddress: 'not-an-ip' });
    expect([res.statusCode, res.json().error]).toEqual([400, 'invalid_argument']);
  });

  it('honours X-Forwarded-For only from trusted proxies (rate limits key on the client address)', async () => {
    // Two clients behind the same socket peer (127.0.0.1) with a limit of one request each.
    for (const [trustProxy, second] of [[false, 429], ['127.0.0.1', 200]] as const) {
      const r = await createTestRelay(10, { trustProxy, ipRateLimit: 1 });
      try {
        const hit = (xff: string) => r.app.inject({ method: 'GET', url: '/v1/descriptors', headers: { 'x-forwarded-for': xff } });
        expect((await hit('198.51.100.1')).statusCode).toBe(200);
        expect((await hit('198.51.100.2')).statusCode).toBe(second);
      } finally {
        await r.close();
      }
    }
  });
});

describe('loadConfig', () => {
  const saved = { ...process.env };
  afterEach(() => { process.env = { ...saved }; });

  it('requires a canonical PUBLIC_RELAY_URL', () => {
    delete process.env.NODE_ENV;
    delete process.env.PUBLIC_RELAY_URL;
    expect(() => loadConfig()).toThrow(/PUBLIC_RELAY_URL is required/);
    process.env.PUBLIC_RELAY_URL = 'https://relay.example.org/';
    expect(() => loadConfig()).toThrow(/not canonical/);
    process.env.PUBLIC_RELAY_URL = 'https://relay.example.org';
    expect(loadConfig().publicRelayUrl).toBe('https://relay.example.org');
    // Plain http only for a loopback development relay.
    process.env.PUBLIC_RELAY_URL = 'http://relay.example.org';
    expect(() => loadConfig()).toThrow(/PUBLIC_RELAY_URL/);
    process.env.PUBLIC_RELAY_URL = 'http://127.0.0.1:3000';
    expect(loadConfig().publicRelayUrl).toBe('http://127.0.0.1:3000');
    process.env.NODE_ENV = 'production';
    process.env.REDIS_URL = 'redis://valkey:6379/0';
    expect(() => loadConfig()).toThrow(/PUBLIC_RELAY_URL/);
  });

  it('fails closed in production: no Redis default, no trust-all proxy', () => {
    process.env.NODE_ENV = 'production';
    process.env.PUBLIC_RELAY_URL = 'https://relay.example.org';
    delete process.env.REDIS_URL;
    delete process.env.REDIS_URL_FILE;
    delete process.env.TRUST_PROXY;
    expect(() => loadConfig()).toThrow(/REDIS_URL/);
    process.env.REDIS_URL = 'redis://valkey:6379/0';
    expect(loadConfig().redisUrl).toBe('redis://valkey:6379/0');
    process.env.TRUST_PROXY = 'true';
    expect(() => loadConfig()).toThrow(/TRUST_PROXY/);
    process.env.TRUST_PROXY = '127.0.0.1,172.18.0.1';
    expect(loadConfig().trustProxy).toBe('127.0.0.1,172.18.0.1');
    // Development keeps the conveniences.
    delete process.env.NODE_ENV;
    delete process.env.REDIS_URL;
    process.env.TRUST_PROXY = 'true';
    expect(loadConfig()).toMatchObject({ redisUrl: 'redis://localhost:6379', trustProxy: true });
  });

  it('defaults retention to the offline window and rejects bad values', () => {
    delete process.env.NODE_ENV;
    process.env.PUBLIC_RELAY_URL = 'https://relay.example.org';
    expect(loadConfig()).toMatchObject({ messageTtlSeconds: 604_800, trustProxy: false });
    process.env.MESSAGE_TTL_SECONDS = '604801';
    expect(() => loadConfig()).toThrow(/MESSAGE_TTL_SECONDS/);
    process.env.MESSAGE_TTL_SECONDS = '3600';
    expect(() => loadConfig()).toThrow(/MESSAGE_TTL_SECONDS/);
    delete process.env.MESSAGE_TTL_SECONDS;
    process.env.TRUST_PROXY = '1';
    expect(() => loadConfig()).toThrow(/hop counts/);
    process.env.TRUST_PROXY = 'loopback,uniquelocal';
    expect(loadConfig().trustProxy).toBe('loopback,uniquelocal');
    process.env.IP_RATE_LIMIT = '1e3';
    expect(() => loadConfig()).toThrow(/IP_RATE_LIMIT/);
    delete process.env.IP_RATE_LIMIT;
    expect(loadConfig()).toMatchObject({
      storageHighWaterBytes: 384 * 1024 * 1024, maxInboxBytes: 24 * 1024 * 1024, maxInboxSenderBytes: 8 * 1024 * 1024,
    });
    process.env.STORAGE_HIGH_WATER_BYTES = '1024';
    expect(() => loadConfig()).toThrow(/STORAGE_HIGH_WATER_BYTES/);
    delete process.env.STORAGE_HIGH_WATER_BYTES;
    expect(loadConfig()).toMatchObject({ registrationNetworkBytes: 96 * 1024 * 1024, trustedRegistrationNetworks: [], trustedRegisterRateLimit: 2000 });
    process.env.TRUSTED_REGISTRATION_NETWORKS = ' 203.0.113.0/24, 2001:db8::/48 ';
    const trusted = loadConfig().trustedRegistrationNetworks;
    expect(trusted.map((t) => t.cidr)).toEqual(['203.0.113.0/24', '2001:db8::/48']);
    expect([trusted[0].list.check('203.0.113.200', 'ipv4'), trusted[0].list.check('203.0.114.1', 'ipv4')]).toEqual([true, false]);
    process.env.TRUSTED_REGISTRATION_NETWORKS = '203.0.113.0';
    expect(() => loadConfig()).toThrow(/TRUSTED_REGISTRATION_NETWORKS/);
  });
});
