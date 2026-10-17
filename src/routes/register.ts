import type { FastifyInstance, FastifyRequest } from 'fastify';
import {
  MAX_PUBLISHED_AGENT_BYTES, eventHashes, extendKel, toBase64, verifyRegistrationRequest, type KelState,
} from '@ace-protocol/sdk';
import { kelDigestOf, type Horizon, type StoredIdentity } from '../store/identity.js';
import { BUSY_RETRY_SECONDS, RelayError, relayBusy, sdk } from '../errors.js';
import {
  authenticate, enforceRegistrationRate, registeredState, registrationNetworkOf, rememberState, type RouteDeps,
} from './shared.js';

/**
 * Safety net only: every `retry` is a committed write of the same identity with an older timestamp, so the re-check
 * ends in `identity_conflict` once the stored timestamp reaches the request's.
 */
const MAX_REGISTER_PASSES = 16;

export interface RegisterDeps extends RouteDeps {
  sseRegistry: { unregistered(aceId: string): Promise<void> };
}

/** A fork is `kel_conflict`; a strict prefix of the stored KEL is `stale_seq`; equal, extended and recovered pass. */
function checkAgainstStored(stored: StoredIdentity, requestKel: unknown[], now: number): void {
  const { outcome } = sdk(() => extendKel(registeredState(stored, now), requestKel, now));
  if (outcome === 'unchanged' && requestKel.length < stored.kel.length) {
    throw new RelayError('stale_seq', 'the request carries a strict prefix of the registered KEL');
  }
}

/** The horizon of a KEL: its last root-epoch event (its last `icp` or `rot`) and its last seq. */
export function epochOf(s: KelState): { epochSeq: number; epochStartHash: string; lastSeq: number } {
  let epochSeq = s.events.length - 1;
  while (s.events[epochSeq].t !== 'icp' && s.events[epochSeq].t !== 'rot') epochSeq--;
  return { epochSeq, epochStartHash: eventHashes(s)[epochSeq], lastSeq: s.events.length - 1 };
}

/**
 * A registration against a retired log whose KEL has expired (07 § Registration), from its fixed-size horizon. The
 * candidate must carry the epoch's first event: a fork at or before it is never a valid recovery under 01 rule 6
 * (`kel_conflict`). It is then accepted when its event at lastSeq is the retired last event (an extension), or when it
 * holds a `rot` after the epoch start, which only the holder of the committed next root can sign (the owner's
 * recovery). Otherwise a candidate ending before lastSeq is `stale_seq` (a prefix, or a fork the relay can no longer
 * tell from one) and any other `kel_conflict`.
 */
function checkAgainstHorizon(h: Horizon, cand: KelState): void {
  const ch = eventHashes(cand);
  if (ch[h.epochSeq] !== h.epochStartHash) throw new RelayError('kel_conflict', 'the KEL does not carry the retired log');
  if (ch[h.lastSeq] === h.lastHash) return; // extended (or equal)
  if (cand.events.some((e, i) => i > h.epochSeq && e.t === 'rot')) return; // recovered
  if (ch.length <= h.lastSeq) throw new RelayError('stale_seq', 'the request carries a shorter log than the retired KEL');
  throw new RelayError('kel_conflict', 'the KEL forks the retired log');
}

export async function registerRoutes(app: FastifyInstance, deps: RegisterDeps): Promise<void> {
  const { identityStore, config } = deps;

  // 07 § Registration.
  app.post('/v1/register', { bodyLimit: MAX_PUBLISHED_AGENT_BYTES }, async (req: FastifyRequest) => {
    await enforceRegistrationRate(deps, req, 'register');
    const now = deps.clock();
    const { request, state, requestDigest } = sdk(() => verifyRegistrationRequest(req.body, { audience: config.publicRelayUrl, clock: () => now }));

    // The store's script compares the version read here; a concurrent change answers `retry` and the request is
    // re-checked against the fresh record.
    for (let pass = 0; pass < MAX_REGISTER_PASSES; pass++) {
      const stored = await identityStore.readHistory(request.aceId);
      if (stored) checkAgainstStored(stored, request.kel, now);
      else {
        // The retired KEL has expired: its permanent horizon still forbids a rollback (07 § Registration).
        const horizon = await identityStore.readHorizon(request.aceId);
        if (horizon) {
          checkAgainstHorizon(horizon, state);
          if (request.timestamp <= horizon.retiredAt) throw new RelayError('identity_conflict');
        }
      }
      if (stored?.retiredAt !== undefined && request.timestamp <= stored.retiredAt) throw new RelayError('identity_conflict');
      if (stored && request.timestamp <= stored.registeredAt) {
        if (request.timestamp === stored.registeredAt && requestDigest === stored.requestDigest) return { ok: true, status: 'idempotent' };
        throw new RelayError('identity_conflict');
      }
      const status = await identityStore.register({
        aceId: request.aceId,
        kel: request.kel,
        seq: state.signing!.seq,
        lastHash: state.lastHash,
        signingPublicKey: toBase64(state.signing!.publicKey),
        timestamp: request.timestamp,
        requestDigest,
        expectedLastHash: stored?.lastHash ?? null,
        expectedRequestDigest: stored?.requestDigest ?? null,
        network: registrationNetworkOf(req, config),
      });
      if (status === 'retry') continue;
      if (status === 'identity_conflict') throw new RelayError('identity_conflict');
      if (status === 'rate_limited') throw new RelayError('rate_limited', 'the registering network is over its storage budget', BUSY_RETRY_SECONDS);
      if (status === 'relay_busy') throw relayBusy();
      if (status !== 'idempotent') rememberState(kelDigestOf(request.kel), state);
      return { ok: true, status };
    }
    req.log.warn({ aceId: request.aceId }, 'registration lost the compare-and-set repeatedly');
    throw new Error(`registration of ${request.aceId} lost the compare-and-set ${MAX_REGISTER_PASSES} times`);
  });

  app.post('/v1/unregister', async (req: FastifyRequest) => {
    const { identity, timestamp } = await authenticate(deps, req, { action: 'unregister' });
    const epoch = epochOf(registeredState(identity, deps.clock()));
    const result = await identityStore.unregister(identity.aceId, timestamp, identity.lastHash, identity.requestDigest, epoch);
    if (result === 'identity_conflict') throw new RelayError('identity_conflict', 'auth timestamp must be newer than the stored registration');
    if (result === 'not_registered') throw new RelayError('not_registered');
    await deps.sseRegistry.unregistered(identity.aceId);
    return { ok: true };
  });
}
