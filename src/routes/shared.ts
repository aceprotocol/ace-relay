import type { FastifyRequest } from 'fastify';
import {
  ACEError, fromBase64, networkKey, parseAuthHeaders, parseIp, toBase64, verifyAuthHeaders, verifyKel, verifyPermit, type KelState,
  type RelayAuthRequest, type Signer,
} from '@ace-protocol/sdk';
import type { IdentityStore, StoredHistory, StoredIdentity } from '../store/identity.js';
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
 * What an operational signature of a stored identity is checked against (01 § Operational signatures): its aceId and
 * current signing delegation, as registration derived them from the verified log. The log itself is not read, so a
 * request costs the same whatever the log's size.
 */
export function signerState(identity: StoredIdentity): Signer {
  const { aceId, seq, delegatedAt, notAfter } = identity;
  return { aceId, signing: { scheme: 'ml-dsa-65', publicKey: fromBase64(identity.signingPublicKey), seq, delegatedAt, notAfter } };
}

/** The verified state of a stored identity's log. A stored log that fails or disagrees with its record is corruption. */
export function registeredState(identity: StoredHistory, now: number): KelState {
  let state: KelState;
  try {
    state = verifyKel(identity.kel, now);
  } catch (e) {
    throw new StorageError(`stored log of ${identity.aceId} does not verify: ${e instanceof Error ? e.message : String(e)}`);
  }
  const s = state.signing;
  if (state.aceId !== identity.aceId || state.lastHash !== identity.lastHash || s === null || s.seq !== identity.seq || s.scheme !== 'ml-dsa-65'
    || toBase64(s.publicKey) !== identity.signingPublicKey || s.notAfter !== identity.notAfter || s.delegatedAt !== identity.delegatedAt) {
    throw new StorageError(`stored identity ${identity.aceId} disagrees with its log`);
  }
  return state;
}

/**
 * The subject of a permit `identity` issued (to `from`, when given), or null on any permit failure. Callers answer
 * every null alike, so a refusal never reveals whether the issuer exists, is private, or why the permit failed.
 */
export function permittedSubject(identity: StoredIdentity, permit: unknown, from: string | undefined, now: number): string | null {
  try {
    return verifyPermit(permit, signerState(identity), from, now).subject;
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

/** 02 relay constants (07 § Client networks). */
const CLIENT_NETWORK_PREFIX_IPV4 = 24;
const CLIENT_NETWORK_PREFIX_IPV6 = 56;

/**
 * The key of the per-route request limit and directory reads: the IPv4 address (an IPv4 /24 is often shared by
 * unrelated actors), the IPv6 client network (a /56 is commonly one site's allocation; a finer key would multiply its
 * limits).
 */
export const clientOf = (req: FastifyRequest): string => keyOf(req, { v4Prefix: 32, v6Prefix: CLIENT_NETWORK_PREFIX_IPV6 });

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
 * Counts a registration, descriptor or card publication against its registration network (`registrationNetworkOf`):
 * `REGISTER_RATE_LIMIT` per client network, `TRUSTED_REGISTER_RATE_LIMIT` per trusted network (a hosted service
 * registers for many end users from one egress).
 */
export async function enforceRegistrationRate(deps: Pick<RouteDeps, 'rateLimiter' | 'config'>, req: FastifyRequest, route: 'register' | 'descriptor' | 'card'): Promise<void> {
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
  sdk(() => verifyAuthHeaders(auth, authReq, signerState(identity), { audience: deps.config.publicRelayUrl, clock: () => now }));
  const nonce = await deps.replayStore.consume(auth.aceId, auth.nonce, drains(authReq));
  if (nonce === 'replay') throw new RelayError('replay');
  if (nonce === 'full') throw relayBusy();
  return { identity, timestamp: auth.timestamp };
}
