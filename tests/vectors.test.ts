// ace-spec test-vectors.json `auth.negative` and `auth.registration.negative`, replayed through the real HTTP routes.
import { readFileSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { SoftwareIdentity, createRegistrationRequest, type RelayAuthRequest } from '@ace-protocol/sdk';
import { createTestRelay, type TestRelay } from './helpers.js';

interface AuthNegative { name: string; agent: string; headers: Record<string, string>; request: RelayAuthRequest; now: number; error: string }
interface RegistrationNegative { name: string; request: unknown; audience: string; now: number; error: string }

const V = JSON.parse(readFileSync(new URL('../../ace-spec/test-vectors.json', import.meta.url), 'utf8')) as {
  now: number;
  agents: Record<string, { aceId: string; export: unknown }>;
  auth: { negative: AuthNegative[]; registration: { request: unknown; audience: string; now: number; negative: RegistrationNegative[] } };
};
const AUDIENCE = 'https://relay.example';

let clock = V.now;
const relays = new Map<string, TestRelay>();
/** The relay at `audience` (one per audience, sharing db 7), on the vector clock. */
async function relayAt(audience: string): Promise<TestRelay> {
  let r = relays.get(audience);
  if (!r) {
    r = await createTestRelay(7, { publicRelayUrl: audience }, { clock: () => clock, flush: relays.size === 0 });
    relays.set(audience, r);
  }
  return r;
}

/** The route of an authenticated action, carrying exactly the vector's headers. */
function call(r: TestRelay, req: RelayAuthRequest, headers: Record<string, string>) {
  switch (req.action) {
    case 'listen':
      return r.app.inject({ method: 'GET', url: `/v1/listen?since=${req.since}`, headers });
    case 'inbox':
      return r.app.inject({ method: 'GET', url: `/v1/inbox?since=${req.since}&limit=${req.limit}`, headers });
    case 'inbox-ack':
      return r.app.inject({ method: 'POST', url: `/v1/inbox/ack?through=${req.through}`, headers });
    case 'block':
      return r.app.inject({ method: 'POST', url: '/v1/blocks', headers, payload: { peer: req.peer, blocked: req.blocked, revision: req.revision } });
    case 'unregister':
      return r.app.inject({ method: 'POST', url: '/v1/unregister', headers });
  }
}

beforeAll(async () => {
  const r = await relayAt(AUDIENCE);
  // The relay holds bob's KEL (the registration vector itself) and carol's (registered while her delegation is live).
  const reg = V.auth.registration;
  clock = reg.now;
  expect((await r.app.inject({ method: 'POST', url: '/v1/register', payload: reg.request as object })).json()).toEqual({ ok: true, status: 'registered' });
  const carol = SoftwareIdentity.fromExport(V.agents.carol.export, V.now);
  const req = await createRegistrationRequest(carol, { audience: AUDIENCE, timestamp: V.now });
  clock = V.now;
  expect((await r.app.inject({ method: 'POST', url: '/v1/register', payload: req })).json()).toEqual({ ok: true, status: 'registered' });
});
afterAll(async () => {
  for (const r of relays.values()) await r.close();
});

describe('auth.negative through the relay routes', () => {
  for (const v of V.auth.negative) {
    it(v.name, async () => {
      clock = v.now;
      const res = await call(await relayAt(AUDIENCE), v.request, v.headers);
      expect(res.json().error).toBe(v.error);
    });
  }
});

describe('auth.registration.negative through POST /v1/register', () => {
  for (const v of V.auth.registration.negative) {
    it(v.name, async () => {
      clock = v.now;
      const res = await (await relayAt(v.audience)).app.inject({ method: 'POST', url: '/v1/register', payload: v.request as object });
      expect(res.json().error).toBe(v.error);
    });
  }
});
