import type { FastifyRequest } from 'fastify';
import {
  ACEError, networkKey, parseAuthHeaders, parseIp, toBase64, verifyAuthHeaders, verifyKel, verifyPermit, type KelState,
  type RelayAuthRequest,
} from '@ace-protocol/sdk';
import type { IdentityStore, StoredIdentity } from '../store/identity.js';
import type { RateLimiter } from '../store/rate-limit.js';
import type { ReplayStore } from '../store/replay.js';
import type { RelayConfig } from '../config.js';
import { RelayError, StorageError, relayBusy, sdk } from '../errors.js';

export interface RouteDeps {
  identityStore: IdentityStore;
  rateLimiter: RateLimiter;
  replayStore: ReplayStore;
  config: RelayConfig;
  /** The relay's protocol clock, Unix seconds. */
  clock: () => number;
}

/**
 * Verified KEL states of stored logs, keyed by StoredIdentity.kelDigest (the SHA-256 of the exact stored JSON). A log
 * verified once stays valid (verifyKel only bounds event timestamps from above), so a hit skips re-verification on the
 * auth, send and resolve paths. Only stored logs enter it. LRU, bounded.
 */
const STATE_CACHE_MAX = 2048;
/** A verified state and the Base64 of its signing key (compared with the stored record on every hit). */
type CachedState = { state: KelState; signingPublicKey: string | null };
const stateCache = new Map<string, CachedState>();

function cache(kelDigest: string, entry: CachedState): void {
  stateCache.delete(kelDigest);
  stateCache.set(kelDigest, entry);
  if (stateCache.size > STATE_CACHE_MAX) stateCache.delete(stateCache.keys().next().value as string);
}

export function rememberState(kelDigest: string, state: KelState): void {
  cache(kelDigest, { state, signingPublicKey: state.signing ? toBase64(state.signing.publicKey) : null });
}

/** The verified state of a stored identity's KEL. A stored log that fails or disagrees with its record is corruption. */
export function registeredState(identity: StoredIdentity, now: number): KelState {
  let entry = stateCache.get(identity.kelDigest);
  if (entry === undefined) {
    let state: KelState;
    try {
      state = verifyKel(identity.kel, now);
    } catch (e) {
      throw new StorageError(`stored log of ${identity.aceId} does not verify: ${e instanceof Error ? e.message : String(e)}`);
    }
    entry = { state, signingPublicKey: state.signing ? toBase64(state.signing.publicKey) : null };
  }
  const { state, signingPublicKey } = entry;
  const s = state.signing;
  if (state.aceId !== identity.aceId || state.lastHash !== identity.lastHash || s === null || s.seq !== identity.seq || s.scheme !== 'ml-dsa-65'
    || signingPublicKey !== identity.signingPublicKey) {
    throw new StorageError(`stored identity ${identity.aceId} disagrees with its log`);
  }
  cache(identity.kelDigest, entry);
  return state;
}

/**
 * The subject of a permit `identity` issued (to `from`, when given), or null on any permit failure. Callers answer
 * every null alike, so a refusal never reveals whether the issuer exists, is private, or why the permit failed.
 */
export function permittedSubject(identity: StoredIdentity, permit: unknown, from: string | undefined, now: number): string | null {
  const state = registeredState(identity, now);
  try {
    return verifyPermit(permit, state, from, now).subject;
  } catch (e) {
    if (e instanceof ACEError) return null;
    throw e;
  }
}

/**
 * Counts one request against `bucket`, keyed on a client network or on identities (see RateLimiter); over the limit
 * throws `rate_limited` with Retry-After, and so does a store with no room for the counter.
 */
export async function enforceRate(rateLimiter: RateLimiter, bucket: string, limit: number, windowSeconds: number,
  keyedOn: 'network' | 'identity'): Promise<void> {
  const rl = await rateLimiter.check(bucket, limit, windowSeconds, keyedOn === 'network');
  if ('full' in rl) throw relayBusy();
  if (!rl.allowed) throw new RelayError('rate_limited', undefined, rl.retryAfter);
}

/** `networkKey` of the client address; one that is not an IP literal is `invalid_argument` (400), never a 500. */
const keyOf = (req: FastifyRequest, o?: { v4Prefix: number; v6Prefix: number }): string => sdk(() => networkKey(req.ip, o));

/** The client's fine network (IPv4 address, IPv6 /64): the per-route request limit and directory reads. */
export const clientOf = (req: FastifyRequest): string => keyOf(req, { v4Prefix: 32, v6Prefix: 64 });

/** 02 constants (07 § Client networks). Import them from the SDK once it exports them. */
const CLIENT_NETWORK_PREFIX_IPV4 = 24;
const CLIENT_NETWORK_PREFIX_IPV6 = 56;

/**
 * The client network (one actor commonly holds a whole IPv6 allocation): registration, descriptor publication,
 * stranger buckets and the stranger allowance share.
 */
export const networkOf = (req: FastifyRequest): string =>
  keyOf(req, { v4Prefix: CLIENT_NETWORK_PREFIX_IPV4, v6Prefix: CLIENT_NETWORK_PREFIX_IPV6 });

/**
 * The network a registration is attributed to for storage (07 § Registration, § Send): `t:<cidr>` for an
 * operator-trusted network, otherwise `n:<client network>`.
 */
export function registrationNetworkOf(req: FastifyRequest, config: RelayConfig): string {
  const ip = parseIp(req.ip);
  if (ip === null) throw new RelayError('invalid_argument', 'client address is not an IP literal');
  // IPv4-mapped IPv6 is judged as its IPv4 address.
  const [address, family] = ip.family === 4 ? [ip.bytes.join('.'), 'ipv4' as const] : [req.ip, 'ipv6' as const];
  for (const { cidr, list } of config.trustedRegistrationNetworks) if (list.check(address, family)) return `t:${cidr}`;
  return `n:${networkOf(req)}`;
}

/**
 * Counts a registration or descriptor publication against its registration network (`registrationNetworkOf`):
 * `REGISTER_RATE_LIMIT` per client network, `TRUSTED_REGISTER_RATE_LIMIT` per trusted network (a hosted service
 * registers for many end users from one egress).
 */
export async function enforceRegistrationRate(deps: Pick<RouteDeps, 'rateLimiter' | 'config'>, req: FastifyRequest, route: 'register' | 'descriptor'): Promise<void> {
  const network = registrationNetworkOf(req, deps.config);
  const limit = network.startsWith('t:') ? deps.config.trustedRegisterRateLimit : deps.config.registerRateLimit;
  await enforceRate(deps.rateLimiter, `${route}:${network}`, limit, 3600, 'network');
}

/** The per-network limit shared by every /v1 route (an onRequest hook in buildApp). */
export async function checkIpRate(deps: Pick<RouteDeps, 'rateLimiter' | 'config'>, req: FastifyRequest): Promise<void> {
  await enforceRate(deps.rateLimiter, `ip:${clientOf(req)}`, deps.config.ipRateLimit, 60, 'network');
}

/** Requests that free memory (or are needed to): their nonce may use the full-store reserve (ReplayStore). */
const drains = (r: RelayAuthRequest): boolean =>
  r.action === 'inbox' || r.action === 'inbox-ack' || r.action === 'unregister' || (r.action === 'block' && !r.blocked)
  || (r.action === 'wake' && r.gateway === undefined);

/**
 * 07 § Authentication: headers (`invalid_argument`) → registered (`not_registered`) → seq (`stale_seq` / `future_seq`)
 * → audience, freshness, signed-while-live, signature → nonce once (`replay`). A failed check consumes no nonce.
 */
export async function authenticate(deps: RouteDeps, req: FastifyRequest, authReq: RelayAuthRequest): Promise<{ identity: StoredIdentity; timestamp: number }> {
  const auth = sdk(() => parseAuthHeaders(req.headers));
  const identity = await deps.identityStore.read(auth.aceId);
  if (!identity) throw new RelayError('not_registered');
  const now = deps.clock();
  const state = registeredState(identity, now);
  sdk(() => verifyAuthHeaders(auth, authReq, state, { audience: deps.config.publicRelayUrl, clock: () => now }));
  const nonce = await deps.replayStore.consume(auth.aceId, auth.nonce, drains(authReq));
  if (nonce === 'replay') throw new RelayError('replay');
  if (nonce === 'full') throw relayBusy();
  return { identity, timestamp: auth.timestamp };
}
