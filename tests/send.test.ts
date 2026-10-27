import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { MAX_PACKET_BYTES, MAX_PLAINTEXT_BYTES, createRegistrationRequest } from '@ace-protocol/sdk';
import {
  ack, authHeaders, block, createTestRelay, inbox, newAgent, now, packet, permit, published, registered, send, type TestRelay,
  RELAY_URL,
} from './helpers.js';
import { HORIZON_BYTES } from '../src/store/identity.js';

let relay: TestRelay;
beforeAll(async () => { relay = await createTestRelay(3); });
afterAll(async () => { await relay.close(); });

const queued = async (aceId: string) => relay.redis.xlen(`ace:inbox:${aceId}`);

describe('POST /v1/send with a permit', () => {
  it('queues for a closed recipient with a permit it issued to the sender; never checks the sender', async () => {
    const to = await published(relay), from = await newAgent(); // the sender is not registered anywhere
    const res = await send(relay, await packet(from, to), await permit(to, from));
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ ok: true });
    expect(await queued(to.aceId)).toBe(1);
  });

  it('refuses permits that do not admit this sender', async () => {
    const to = await published(relay, { age: 1000 /* seconds: so the expired permit below is not clamped up */ }), from = await newAgent(), other = await registered(relay);
    const p = await packet(from, to);
    const notPermitted = async (permitValue: unknown) => {
      const res = await send(relay, p, permitValue);
      expect(res.statusCode).toBe(403);
      expect(res.json().error).toBe('not_permitted');
    };
    await notPermitted(await permit(to, other)); // subject != from
    await notPermitted(await permit(other, from)); // issuer != to
    await notPermitted(await permit(to, from, { now: now() - 100, ttl: 50 })); // expired
    await notPermitted({ ...(await permit(to, from)), id: crypto.randomUUID() }); // signature
    await notPermitted('nonsense');
    expect(await queued(to.aceId)).toBe(0);
  });

  it('a block wins over an unexpired permit', async () => {
    const to = await published(relay), from = await newAgent();
    const p = await permit(to, from);
    expect((await block(relay, to, from.aceId, true, 1)).statusCode).toBe(200);
    expect((await send(relay, await packet(from, to), p)).json().error).toBe('not_permitted');
    expect((await block(relay, to, from.aceId, false, 2)).statusCode).toBe(200);
    expect((await send(relay, await packet(from, to), p)).statusCode).toBe(200);
  });

  it('bounds the normal queue in entries and bytes', async () => {
    const small = await createTestRelay(15, { maxInboxEntries: 2, maxInboxBytes: MAX_PACKET_BYTES });
    try {
      const to = await published(small), from = await newAgent();
      const p = await permit(to, from);
      expect((await send(small, await packet(from, to), p)).statusCode).toBe(200);
      expect((await send(small, await packet(from, to), p)).statusCode).toBe(200);
      const full = await send(small, await packet(from, to), p);
      expect(full.statusCode).toBe(429);
      expect(full.json().error).toBe('recipient_inbox_full');
      const page = (await inbox(small, to)).json();
      expect(page.messages).toHaveLength(2);
    } finally {
      await small.close();
    }
  });

  it('rate-limits permitted sends per (recipient, sender)', async () => {
    const limited = await createTestRelay(15, { sendRateLimit: 1 });
    try {
      const to = await published(limited), from = await newAgent();
      const p = await permit(to, from);
      expect((await send(limited, await packet(from, to), p)).statusCode).toBe(200);
      expect((await send(limited, await packet(from, to), p)).json().error).toBe('rate_limited');
    } finally {
      await limited.close();
    }
  });
});

describe('POST /v1/send without a permit (stranger allowance)', () => {
  it('requires a recipient whose card record is contact: open', async () => {
    const closed = await published(relay, { contact: 'closed' }), open = await published(relay, { contact: 'open' }), from = await newAgent();
    expect((await send(relay, await packet(from, closed))).json().error).toBe('not_permitted');
    expect((await send(relay, await packet(from, open))).statusCode).toBe(200);
    const unpublished = await registered(relay);
    expect((await send(relay, await packet(from, unpublished))).json().error).toBe('not_permitted');
  });

  it('holds at most 16 stranger entries per recipient, beside the normal queue', async () => {
    const to = await published(relay, { contact: 'open' });
    const strangers = await Promise.all(Array.from({ length: 17 }, () => newAgent()));
    // At most STRANGER_NETWORK_ALLOWANCE (2) per client network: sixteen entries from eight /24s.
    const from = (i: number) => `198.18.${Math.floor(i / 2)}.${i}`;
    for (let i = 0; i < 16; i++) expect((await send(relay, await packet(strangers[i], to), undefined, from(i))).statusCode).toBe(200);
    const full = await send(relay, await packet(strangers[16], to), undefined, '192.0.2.200');
    expect(full.statusCode).toBe(429);
    expect(full.json().error).toBe('recipient_inbox_full');
    // Permitted senders are unaffected.
    expect((await send(relay, await packet(strangers[16], to), await permit(to, strangers[16]))).statusCode).toBe(200);
    expect(await relay.redis.hgetall(`ace:inbox-meta:${to.aceId}`)).toMatchObject({ sn: '16', nn: '1' });
    expect(await relay.redis.zcard(`ace:inbox-strangers:${to.aceId}`)).toBe(16);
  });

  it('rate-limits strangers per client network and per recipient', async () => {
    const limited = await createTestRelay(15, { strangerIpRateLimit: 1, strangerRecipientRateLimit: 2 });
    try {
      const to = await published(limited, { contact: 'open' });
      const s = await newAgent();
      expect((await send(limited, await packet(s, to), undefined, '203.0.113.7')).statusCode).toBe(200);
      expect((await send(limited, await packet(s, to), undefined, '203.0.113.7')).json().error).toBe('rate_limited');
      // IPv4 is aggregated by /24 for stranger buckets.
      expect((await send(limited, await packet(s, to), undefined, '203.0.113.8')).json().error).toBe('rate_limited');
      expect((await send(limited, await packet(s, to), undefined, '198.51.100.8')).statusCode).toBe(200);
      const res = await send(limited, await packet(s, to), undefined, '192.0.2.9');
      expect(res.statusCode).toBe(429);
      expect(res.json().error).toBe('rate_limited');
    } finally {
      await limited.close();
    }
  });
});

describe('POST /v1/send validation', () => {
  it('rejects malformed bodies and packets, unknown recipients (as not_permitted) and timestamps outside the window', async () => {
    const to = await published(relay, { contact: 'open' }), from = await newAgent(604_900 /* seconds: older than the offline window */);
    const p = await packet(from, to);
    expect((await send(relay, { ...p, ace: '2' })).json().error).toBe('unsupported_version');
    expect((await send(relay, { ...p, extra: 1 })).json().error).toBe('invalid_packet');
    expect((await send(relay, { ...p, to: p.from })).json().error).toBe('invalid_packet');
    // 03 § Decoding: an oversize payload is invalid_packet, straight from the SDK decoder
    const huge = 'A'.repeat(4 * Math.ceil((MAX_PLAINTEXT_BYTES + 29) / 3));
    expect((await send(relay, { ...p, encryption: { ...p.encryption, payload: huge } })).json().error).toBe('invalid_packet');
    const extra = await relay.app.inject({ method: 'POST', url: '/v1/send', payload: { packet: p, source: {} } });
    expect(extra.json().error).toBe('invalid_argument');
    expect((await relay.app.inject({ method: 'POST', url: '/v1/send', payload: {} })).json().error).toBe('invalid_argument');
    const unknown = await newAgent();
    unknown.vault = to.vault;
    const res = await send(relay, await packet(from, unknown));
    expect(res.statusCode).toBe(403);
    expect(res.json()).toEqual({ error: 'not_permitted', message: 'not permitted' });
    expect((await send(relay, await packet(from, to, { timestamp: now() + 400 }))).json().error).toBe('stale_timestamp');
    expect((await send(relay, await packet(from, to, { timestamp: now() - 604_900 }))).json().error).toBe('stale_timestamp');
    // Six days old is still inside the offline window.
    expect((await send(relay, await packet(from, to, { timestamp: now() - 6 * 86_400 }))).statusCode).toBe(200);
  });

  it('a body over its limit is payload_too_large', async () => {
    const res = await relay.app.inject({
      method: 'POST', url: '/v1/send', headers: { 'content-type': 'application/json' },
      payload: JSON.stringify({ packet: 'x'.repeat(MAX_PACKET_BYTES + 70_000) }),
    });
    expect(res.statusCode).toBe(413);
    expect(res.json().error).toBe('payload_too_large');
  });

  it('an identical packet is accepted again without enqueuing, even when the allowance is full', async () => {
    const to = await published(relay, { contact: 'open' }), from = await newAgent();
    const p = await packet(from, to);
    expect((await send(relay, p)).statusCode).toBe(200);
    expect((await send(relay, JSON.parse(JSON.stringify(p)))).statusCode).toBe(200);
    expect(await queued(to.aceId)).toBe(1);
    // A retry re-encrypts and re-signs under the same messageId: a different packet, queued (the receiver dedups).
    expect((await send(relay, await packet(from, to, { messageId: p.messageId }))).statusCode).toBe(200);
    expect(await queued(to.aceId)).toBe(2);
    // After an ack the packet is no longer queued and may be queued again.
    const page = (await inbox(relay, to)).json();
    expect((await ack(relay, to, page.cursor)).statusCode).toBe(200);
    expect((await send(relay, p)).statusCode).toBe(200);
    expect(await queued(to.aceId)).toBe(1);
  });
});

// Regression: review 2026-10-14 M4 — permit-less and blocked sends must not reveal registration, contact or blocks.
describe('POST /v1/send admission is not an oracle', () => {
  it('unknown, closed, card-less, blocking recipients and bad permits all answer the same 403', async () => {
    const from = await newAgent();
    const pub = await published(relay, { contact: 'open' }), priv = await published(relay, { contact: 'closed' }), bare = await registered(relay);
    const unknown = await newAgent();
    expect((await block(relay, pub, from.aceId, true, 1)).statusCode).toBe(200);
    expect((await block(relay, priv, from.aceId, true, 1)).statusCode).toBe(200);
    const blockedWithPermit = await published(relay);
    const p = await permit(blockedWithPermit, from);
    expect((await block(relay, blockedWithPermit, from.aceId, true, 1)).statusCode).toBe(200);
    const answers = [
      await send(relay, await packet(from, unknown)), // unknown recipient, no permit
      await send(relay, await packet(from, unknown), await permit(unknown, from)), // unknown recipient, self-made permit
      await send(relay, await packet(from, priv)), // closed and blocking, no permit
      await send(relay, await packet(from, bare)), // registered, unpublished
      await send(relay, await packet(from, pub)), // open, blocks the sender
      await send(relay, await packet(from, priv), await permit(bare, from)), // wrong issuer, blocking recipient
      await send(relay, await packet(from, blockedWithPermit), p), // valid permit, blocked
    ];
    for (const res of answers) {
      expect(res.statusCode).toBe(403);
      expect(res.json()).toEqual({ error: 'not_permitted', message: 'not permitted' });
    }
  });

  // Review 2026-10-21 SP7: the block check precedes the identical-bytes check (07 § Send steps 2–3).
  it('a blocked sender resending a packet still queued gets not_permitted, not the queue state', async () => {
    const to = await published(relay), from = await newAgent();
    const pm = await permit(to, from);
    const p = await packet(from, to);
    expect((await send(relay, p, pm)).statusCode).toBe(200);
    expect(await queued(to.aceId)).toBe(1);
    expect((await block(relay, to, from.aceId, true, 1)).statusCode).toBe(200);
    for (const res of [await send(relay, p, pm), await send(relay, p)]) {
      expect(res.statusCode).toBe(403);
      expect(res.json()).toEqual({ error: 'not_permitted', message: 'not permitted' });
    }
    expect(await queued(to.aceId)).toBe(1);
  });
});

const big = (from: Parameters<typeof packet>[0], to: Parameters<typeof packet>[1]) => packet(from, to, { message: 'y'.repeat(1_100_000) });

// Regression: review 2026-10-14 H1 — storage exhaustion through self-issued permits (PoC: storage.test.ts, oom.test.ts),
// and the follow-up review of b8dcd2a: no relay-wide budget keyed on the unauthenticated `from` or on a shared egress.
describe('storage is charged to the recipient', () => {
  it('charges storage to the recipient: two networks hold only their recipients\' queues', async () => {
    // Each recipient holds about two big packets; two registrations per /24 per hour.
    const r = await createTestRelay(15, { maxInboxBytes: 2 * MAX_PACKET_BYTES, registerRateLimit: 2 });
    try {
      const fill = async (net: string) => {
        const recipients = [];
        for (let i = 0; i < 3; i++) {
          const a = await newAgent();
          const res = await r.app.inject({ method: 'POST', url: '/v1/register', payload: await createRegistrationRequest(a.id, { audience: RELAY_URL }), remoteAddress: net });
          if (res.statusCode !== 200) {
            expect(res.json().error).toBe('rate_limited');
            break;
          }
          recipients.push(a);
        }
        expect(recipients).toHaveLength(2);
        for (const a of recipients) {
          for (let j = 0; j < 4; j++) {
            const b = await newAgent(); // throwaway sender keys do not help: the recipient's queue is the budget
            const res = await send(r, await big(b, a), await permit(a, b), net);
            if (res.statusCode !== 200) {
              expect(res.json().error).toBe('recipient_inbox_full');
              break;
            }
          }
        }
      };
      await fill('203.0.113.7');
      await fill('198.51.100.7');
      const held = await Promise.all(['n:203.0.113.0/24', 'n:198.51.100.0/24'].map((n) => r.messageStore.registrationNetworkBytes(n)));
      expect(held[0] + held[1]).toBeLessThanOrEqual(8 * MAX_PACKET_BYTES);
      // Everyone else still sends.
      const c = await registered(r), d = await newAgent();
      expect((await send(r, await big(d, c), await permit(c, d), '192.0.2.1')).statusCode).toBe(200);
    } finally {
      await r.close();
    }
  }, 120_000);

  it('many identities behind one address each use their recipients\' quotas', async () => {
    const r = await createTestRelay(15, { maxInboxBytes: 2 * MAX_PACKET_BYTES });
    try {
      for (let i = 0; i < 6; i++) { // e.g. a hosted service: every sender on one egress IP
        const a = await registered(r), b = await newAgent(), p = await permit(a, b);
        for (let j = 0; j < 2; j++) expect((await send(r, await big(b, a), p, '203.0.113.7')).statusCode).toBe(200);
      }
    } finally {
      await r.close();
    }
  }, 120_000);

  it('bounds one sender\'s share of a recipient queue; a forged-from flood cannot stop the victim sending elsewhere', async () => {
    const r = await createTestRelay(15, { maxInboxSenderBytes: MAX_PACKET_BYTES });
    try {
      const attacker = await registered(r), victim = await newAgent(), b = await registered(r), c = await newAgent();
      // The attacker issues its own permit to subject = victim and floods with from = victim.
      const forged = await permit(attacker, victim);
      expect((await send(r, await big(victim, attacker), forged)).statusCode).toBe(200);
      const res = await send(r, await big(victim, attacker), forged);
      expect(res.statusCode).toBe(429);
      expect(res.json()).toEqual({ error: 'recipient_inbox_full', message: "sender's share of the recipient queue is full" });
      // Other senders to the same recipient are unaffected, and so is the victim towards anyone else.
      expect((await send(r, await big(c, attacker), await permit(attacker, c))).statusCode).toBe(200);
      expect((await send(r, await big(victim, b), await permit(b, victim))).statusCode).toBe(200);
      // Acknowledging frees the share.
      const page = (await inbox(r, attacker)).json();
      expect((await ack(r, attacker, page.cursor)).statusCode).toBe(200);
      expect(await r.redis.hget(`ace:inbox-meta:${attacker.aceId}`, `fb:${victim.aceId}`)).toBeNull();
    } finally {
      await r.close();
    }
  }, 60_000);
});

// Regression: review of 8007c16 — one /24 registering many identities must not fill the backstop. Storage is also
// charged to the network each recipient registered from.
describe('storage is charged to the registering network', () => {
  const registerFrom = async (r: TestRelay, net: string, timestamp?: number, agent?: Parameters<typeof packet>[0]) => {
    const a = agent ?? await newAgent();
    const res = await r.app.inject({ method: 'POST', url: '/v1/register', payload: await createRegistrationRequest(a.id, { audience: RELAY_URL, timestamp: timestamp }), remoteAddress: net });
    expect(res.statusCode).toBe(200);
    return a;
  };
  /** Sends big packets to `a` from fresh senders until one is refused; returns the refusal. */
  const fillUntilRefused = async (r: TestRelay, a: Parameters<typeof packet>[1], max: number) => {
    for (let i = 0; i < max; i++) {
      const b = await newAgent();
      const res = await send(r, await big(b, a), await permit(a, b), '192.0.2.50');
      if (res.statusCode !== 200) return res;
    }
    return undefined;
  };

  it('one /24 registering many identities stays within its budget; other networks are unaffected', async () => {
    const r = await createTestRelay(15, { maxInboxBytes: 2 * MAX_PACKET_BYTES, registrationNetworkBytes: 3 * MAX_PACKET_BYTES });
    try {
      let refusal;
      for (let i = 0; i < 4; i++) {
        const a = await registerFrom(r, `203.0.113.${10 + i}`); // distinct hosts, one /24
        const res = await fillUntilRefused(r, a, 3); // each queue holds two; the third is recipient_inbox_full ...
        if (res?.json().error === 'rate_limited') refusal ??= res; // ... until the network's budget runs out
      }
      expect(refusal!.statusCode).toBe(429);
      expect(refusal!.json()).toEqual({ error: 'rate_limited', message: "the recipient's registration network is over its storage budget" });
      expect(refusal!.headers['retry-after']).toMatch(/^\d+$/);
      expect(await r.messageStore.registrationNetworkBytes('n:203.0.113.0/24')).toBeLessThanOrEqual(3 * MAX_PACKET_BYTES);
      // Two more networks fill their own budgets ...
      for (const net of ['198.51.100.1', '2001:db8:aa::1']) {
        for (let i = 0; i < 2; i++) await fillUntilRefused(r, await registerFrom(r, net), 3);
      }
      for (const net of ['n:198.51.100.0/24', 'n:2001:db8:aa::/56']) {
        expect(await r.messageStore.registrationNetworkBytes(net)).toBeLessThanOrEqual(3 * MAX_PACKET_BYTES);
      }
      // ... and a recipient registered elsewhere is unaffected.
      const c = await registerFrom(r, '192.0.2.7'), d = await newAgent();
      const ok = await send(r, await packet(d, c), await permit(c, d));
      expect(ok.statusCode).toBe(200);
    } finally {
      await r.close();
    }
  }, 180_000);

  it('a trusted registration network gets the larger budget', async () => {
    const r = await createTestRelay(15, {
      maxInboxBytes: 2 * MAX_PACKET_BYTES, registrationNetworkBytes: MAX_PACKET_BYTES,
      trustedRegistrationNetworks: ['203.0.113.0/24'], trustedRegistrationNetworkBytes: 16 * MAX_PACKET_BYTES,
    });
    try {
      for (let i = 0; i < 3; i++) { // e.g. a hosted service: every identity registered from one egress
        const a = await registerFrom(r, '203.0.113.7');
        for (let j = 0; j < 2; j++) {
          const b = await newAgent();
          expect((await send(r, await big(b, a), await permit(a, b))).statusCode).toBe(200);
        }
      }
      expect(await r.messageStore.registrationNetworkBytes('t:203.0.113.0/24')).toBeGreaterThan(4 * MAX_PACKET_BYTES);
      // An untrusted /24 is held to the small budget.
      const u = await registerFrom(r, '198.51.100.7');
      expect((await fillUntilRefused(r, u, 3))!.json().error).toBe('rate_limited');
    } finally {
      await r.close();
    }
  }, 120_000);

  it('re-registration from another network moves the attribution; ack and unregister release it', async () => {
    const r = await createTestRelay(15);
    try {
      const a = await registerFrom(r, '203.0.113.7'), b = await newAgent(), p = await permit(a, b);
      const kelBytes = Buffer.byteLength(JSON.stringify(a.id.getKel()));
      expect((await send(r, await packet(b, a), p)).statusCode).toBe(200);
      const first = await r.messageStore.registrationNetworkBytes('n:203.0.113.0/24');
      expect(first).toBeGreaterThan(kelBytes);
      await registerFrom(r, '198.51.100.7', now() + 1, a);
      expect((await send(r, await packet(b, a), p)).statusCode).toBe(200);
      expect(await r.messageStore.registrationNetworkBytes('n:203.0.113.0/24')).toBe(0);
      expect(await r.messageStore.registrationNetworkBytes('n:198.51.100.0/24')).toBeGreaterThan(first);
      const page = (await inbox(r, a)).json();
      expect((await ack(r, a, page.messages[0].streamId)).statusCode).toBe(200);
      expect(await r.messageStore.registrationNetworkBytes('n:198.51.100.0/24')).toBeLessThan(2 * first);
      const un = await r.app.inject({ method: 'POST', url: '/v1/unregister', headers: await authHeaders(a, { action: 'unregister' }, now() + 2) });
      expect(un.statusCode).toBe(200);
      // The queue is released; the retired KEL stays charged while the relay keeps it, the horizon for good.
      expect(await r.messageStore.registrationNetworkBytes('n:198.51.100.0/24')).toBe(kelBytes + HORIZON_BYTES);
    } finally {
      await r.close();
    }
  }, 60_000);
});

// Regression: review 2026-10-14 M3 — one network must not occupy a recipient's whole stranger allowance (A7).
describe('stranger fairness per client network', () => {
  it('caps one network\'s entries in the allowance at STRANGER_NETWORK_ALLOWANCE; an ack frees them', async () => {
    const r = await createTestRelay(15);
    try {
      const to = await published(r, { contact: 'open' });
      for (let i = 0; i < 2; i++) expect((await send(r, await packet(await newAgent(), to), undefined, `203.0.113.${i}`)).statusCode).toBe(200);
      const full = await send(r, await packet(await newAgent(), to), undefined, '203.0.113.200');
      expect(full.json()).toEqual({ error: 'recipient_inbox_full', message: 'stranger allowance share of this client network is full' });
      expect((await send(r, await packet(await newAgent(), to), undefined, '2001:db8:1:2::1')).statusCode).toBe(200);
      // Acknowledging frees the network's slots.
      const page = (await inbox(r, to)).json();
      expect((await ack(r, to, page.cursor)).statusCode).toBe(200);
      expect(await r.redis.hget(`ace:inbox-meta:${to.aceId}`, 'sc:203.0.113.0/24')).toBeNull();
      expect((await send(r, await packet(await newAgent(), to), undefined, '203.0.113.5')).statusCode).toBe(200);
    } finally {
      await r.close();
    }
  }, 60_000);
});
