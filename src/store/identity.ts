import type Redis from 'ioredis';
import { OFFLINE_WINDOW_SECONDS, isACEId, sha256Hex, type KelEvent } from '@ace-protocol/sdk';
import { RelayError } from '../errors.js';
import {
  BLOCKS_KEY_PREFIX, DESCRIPTOR_KEY_PREFIX, DIRECTORY_KEY, HANDLE_KEY_PREFIX, HORIZON_KEY_PREFIX, IDENTITY_KEY_PREFIX, WAKE_KEY_PREFIX,
  queueKeys,
} from './keyspace.js';
import { BYTES_LUA, CAPACITY_LUA, IDENTITY_LUA, MAY_GROW, RUNS_WHEN_FULL, budgetArgs, type ByteBudget } from './lua.js';

/** Identity-only registration state. Public metadata lives in signed descriptors. */
export interface StoredIdentity {
  aceId: string;
  kel: KelEvent[]; // the verified identity log
  kelDigest: string; // hex SHA-256 of the stored kel JSON string (keys the routes' verified-state cache)
  seq: number; // the log's current signing delegation (X-ACE-Seq / signature.seq must equal it)
  lastHash: string; // hex SHA-256 of the log's last event; `rotated` = it changed
  signingPublicKey: string; // canonical Base64 of the delegated ml-dsa-65 key
  registeredAt: number; // the verified request timestamp
  requestDigest: string;
  retiredAt?: number;
}

/**
 * The permanent anti-rollback record of an unregistered identity, kept after its KEL expired (fixed size): the
 * registration barrier, the seq and hash of the KEL's last root-epoch event (its last `icp` or `rot`) and of its last
 * event. A registration is checked against it in the register route; the descriptor horizon is restored on
 * re-registration.
 */
export interface Horizon {
  retiredAt: number;
  epochSeq: number;
  epochStartHash: string;
  lastSeq: number;
  lastHash: string;
}

/** Bytes a horizon is charged permanently to its registration network: an upper bound of its stored size. */
export const HORIZON_BYTES = 512;

/** Hex SHA-256 of the kel JSON exactly as register() stores it (`JSON.stringify(kel)`). */
export function kelDigestOf(kel: readonly KelEvent[]): string {
  return sha256Hex(JSON.stringify(kel));
}

/** `IDENTITY_KEY_PREFIX + aceId`, only for a valid ACE ID (never a glob, never another key). */
function identityKey(aceId: string): string {
  if (!isACEId(aceId)) throw new RelayError('invalid_argument', 'aceId must be an ACE ID');
  return IDENTITY_KEY_PREFIX + aceId;
}

export interface StoreLogger {
  error(obj: object, msg: string): void;
}

export const consoleLogger: StoreLogger = {
  error: (obj, msg) => console.error(msg, obj),
};

/**
 * An identity hash as register() wrote it; absent `signingPublicKey` means not registered. The route verifies the log
 * against the record (registeredState), so a corrupt record fails the request there (500), never as a client code.
 */
function parseIdentityHash(aceId: string, d: Record<string, string>): StoredIdentity | null {
  if (d.signingPublicKey === undefined) return null;
  return {
    aceId,
    kel: JSON.parse(d.kel) as KelEvent[],
    kelDigest: sha256Hex(d.kel),
    seq: Number(d.seq),
    lastHash: d.lastHash,
    signingPublicKey: d.signingPublicKey,
    registeredAt: Number(d.registeredAt),
    requestDigest: d.requestDigest,
    ...(d.retiredAt === undefined ? {} : { retiredAt: Number(d.retiredAt) }),
  };
}

// KEYS: identity, descriptor, horizon. ARGV: kel, seq, lastHash, signingPublicKey, timestamp, requestDigest, expected lastHash,
// expected requestDigest, network, then the ByteBudget. The KEL's bytes (and a stored descriptor's) are charged to the
// network registered from; a registration over its budget (`rate_limited`), or one that grows the store at the
// high-water mark (`relay_busy`), is refused. A retired identity's KEL charge already lapses with the packet window
// (see unregister), so a re-registration charges it afresh.
const REGISTER_IDENTITY_SCRIPT = MAY_GROW + BYTES_LUA + CAPACITY_LUA + `
local timestamp = tonumber(ARGV[5])
local retiredAt = tonumber(redis.call('HGET', KEYS[1], 'retiredAt') or '-1')
if timestamp <= retiredAt then return 'identity_conflict' end
if timestamp <= tonumber(redis.call('HGET', KEYS[3], 'retiredAt') or '-1') then return 'identity_conflict' end
local status = 'registered'
local active = false
if redis.call('HEXISTS', KEYS[1], 'signingPublicKey') == 1 then
  if redis.call('HGET', KEYS[1], 'lastHash') ~= ARGV[7]
    or redis.call('HGET', KEYS[1], 'requestDigest') ~= ARGV[8] then return 'retry' end
  local current = tonumber(redis.call('HGET', KEYS[1], 'registeredAt'))
  if timestamp < current then return 'identity_conflict' end
  if timestamp == current then
    if redis.call('HGET', KEYS[1], 'requestDigest') == ARGV[6] then return 'idempotent' end
    return 'identity_conflict'
  end
  status = 'refreshed'
  if ARGV[3] ~= ARGV[7] then status = 'rotated' end
  if retiredAt >= 0 then status = 'registered' else active = true end
elseif ARGV[7] ~= '' or ARGV[8] ~= '' then
  return 'retry'
end
local rn, kb = ARGV[9], #ARGV[1]
local jb = tonumber(redis.call('HGET', KEYS[2], 'jb') or '0')
-- Block records (bb) and the wake registration (wb) belong to an active identity only (unregister deletes them).
local bb, wb = 0, 0
if active then
  bb = tonumber(redis.call('HGET', KEYS[1], 'bb') or '0')
  wb = tonumber(redis.call('HGET', KEYS[1], 'wb') or '0')
end
local held, old = 0, redis.call('HGET', KEYS[1], 'regnet')
if active then held = tonumber(redis.call('HGET', KEYS[1], 'kb') or '0') + jb + bb + wb end
local need = kb + jb + bb + wb
if old == rn then need = need - held end
if overBudget(rn, need, tonumber(ARGV[10]), tonumber(ARGV[11]), tonumber(ARGV[12]), tonumber(ARGV[13])) then return 'rate_limited' end
if need > 0 and atCapacity(tonumber(ARGV[14])) then return 'relay_busy' end
if held > 0 then charge(old, -held) end
charge(rn, kb + jb + bb + wb)
redis.call('HSET', KEYS[1], 'kel', ARGV[1], 'seq', ARGV[2], 'lastHash', ARGV[3], 'signingPublicKey', ARGV[4],
  'registeredAt', ARGV[5], 'requestDigest', ARGV[6], 'regnet', rn, 'kb', kb)
redis.call('HDEL', KEYS[1], 'retiredAt')
redis.call('PERSIST', KEYS[1])
redis.call('PERSIST', KEYS[2])
-- The descriptor horizon outlives an expired descriptor record.
local issuedAt = redis.call('HGET', KEYS[3], 'issuedAt')
if issuedAt and redis.call('HEXISTS', KEYS[2], 'issuedAt') == 0 then
  redis.call('HSET', KEYS[2], 'issuedAt', issuedAt, 'digest', redis.call('HGET', KEYS[3], 'digest'))
end
return status
`;

// KEYS: identity, descriptor, directory, blocks, inbox, inbox-meta, inbox-dedup, inbox-strangers, horizon. ARGV: auth
// timestamp, aceId, expected lastHash, expected requestDigest, the ByteBudget (5), epochSeq, epochStartHash, lastSeq.
// It frees far more than the horizon it writes, so it runs even when the store is full. The handle key is derived from the stored descriptor (see keyspace). Deletes queue, descriptor
// document, handle, directory entry and blocks; keeps the KEL, the descriptor's issuedAt/digest and a retiredAt
// barrier for OFFLINE_WINDOW_SECONDS, and the fixed-size horizon (Horizon) forever (07 § Registration). The wake
// registration (derived key) goes too. The descriptor's, blocks' and wake charges are released; the KEL's lapses with
// the packet window.
const UNREGISTER_IDENTITY_SCRIPT = RUNS_WHEN_FULL + IDENTITY_LUA + BYTES_LUA + `
if not isActive(KEYS[1]) then return 'not_registered' end
if redis.call('HGET', KEYS[1], 'lastHash') ~= ARGV[3] or redis.call('HGET', KEYS[1], 'requestDigest') ~= ARGV[4] then return 'identity_conflict' end
if tonumber(ARGV[1]) <= tonumber(redis.call('HGET', KEYS[1], 'registeredAt')) then return 'identity_conflict' end
local handle = redis.call('HGET', KEYS[2], 'handle') or ''
if handle ~= '' and redis.call('GET', '${HANDLE_KEY_PREFIX}' .. handle) == ARGV[2] then redis.call('DEL', '${HANDLE_KEY_PREFIX}' .. handle) end
local rn = redis.call('HGET', KEYS[1], 'regnet')
charge(rn, -tonumber(redis.call('HGET', KEYS[2], 'jb') or '0') - tonumber(redis.call('HGET', KEYS[1], 'bb') or '0')
  - tonumber(redis.call('HGET', KEYS[1], 'wb') or '0'))
redis.call('HDEL', KEYS[1], 'bb', 'wb')
redis.call('DEL', '${WAKE_KEY_PREFIX}' .. ARGV[2])
retire(rn, tonumber(redis.call('HGET', KEYS[1], 'kb') or '0'), tonumber(ARGV[5]), tonumber(ARGV[6]))
redis.call('HDEL', KEYS[2], 'json', 'handle', 'lastHash', 'jb')
redis.call('ZREM', KEYS[3], ARGV[2])
releaseQueue(KEYS[6])
redis.call('DEL', KEYS[4], KEYS[5], KEYS[6], KEYS[7], KEYS[8])
redis.call('HSET', KEYS[1], 'retiredAt', ARGV[1])
redis.call('EXPIRE', KEYS[1], ${OFFLINE_WINDOW_SECONDS})
-- One horizon per ACE ID, charged once (to the network the identity first retired from) and never released.
if redis.call('EXISTS', KEYS[9]) == 0 then charge(rn, ${HORIZON_BYTES}) end
redis.call('DEL', KEYS[9])
redis.call('HSET', KEYS[9], 'retiredAt', ARGV[1], 'epochSeq', ARGV[10], 'epochStartHash', ARGV[11], 'lastSeq', ARGV[12],
  'lastHash', ARGV[3])
local issuedAt = redis.call('HGET', KEYS[2], 'issuedAt')
if issuedAt then redis.call('HSET', KEYS[9], 'issuedAt', issuedAt, 'digest', redis.call('HGET', KEYS[2], 'digest')) end
if redis.call('EXISTS', KEYS[2]) == 1 then redis.call('EXPIRE', KEYS[2], ${OFFLINE_WINDOW_SECONDS}) end
return 'removed'
`;

/**
 * `retry`: the stored version (lastHash, requestDigest) changed between the route's read and the write; the route
 * re-reads and re-checks. `rate_limited`: the registering network is over its byte budget. `relay_busy`: the store is
 * at the relay-wide high-water mark.
 */
export type RegistrationStatus = 'registered' | 'idempotent' | 'refreshed' | 'rotated' | 'identity_conflict' | 'retry' | 'rate_limited'
  | 'relay_busy';
export type UnregisterStatus = 'removed' | 'not_registered' | 'identity_conflict';

export interface RegistrationWrite {
  aceId: string;
  /** The request's verified log and the fields derived from it. */
  kel: KelEvent[];
  seq: number;
  lastHash: string;
  signingPublicKey: string;
  timestamp: number;
  requestDigest: string;
  /**
   * The stored version the route read: its lastHash and requestDigest (both null: no identity). Any other stored
   * state → `retry`, nothing written.
   */
  expectedLastHash: string | null;
  expectedRequestDigest: string | null;
  /** The registration's network (`registrationNetworkOf`), charged with the stored bytes and recorded as `regnet`. */
  network: string;
}

type ScriptRedis = Redis & {
  registerIdentity(...keysAndArgs: string[]): Promise<RegistrationStatus>;
  unregisterIdentity(...keysAndArgs: string[]): Promise<UnregisterStatus>;
};

export class IdentityStore {
  private redis: ScriptRedis;

  constructor(redis: Redis, private readonly budget: ByteBudget) {
    this.redis = redis as ScriptRedis;
    redis.defineCommand('registerIdentity', { numberOfKeys: 3, lua: REGISTER_IDENTITY_SCRIPT });
    redis.defineCommand('unregisterIdentity', { numberOfKeys: 9, lua: UNREGISTER_IDENTITY_SCRIPT });
  }

  /** The active registration, or null. */
  async read(aceId: string): Promise<StoredIdentity | null> {
    const history = await this.readHistory(aceId);
    return history?.retiredAt === undefined ? history : null;
  }

  /** The requestDigest of the active registration, or null; reads two fields, not the KEL (listen streams). */
  async currentRequestDigest(aceId: string): Promise<string | null> {
    const [digest, retiredAt] = await this.redis.hmget(identityKey(aceId), 'requestDigest', 'retiredAt');
    return retiredAt === null ? digest : null;
  }

  /** The verified KEL horizon survives retirement (for OFFLINE_WINDOW_SECONDS); only registration may use it. */
  async readHistory(aceId: string): Promise<StoredIdentity | null> {
    return parseIdentityHash(aceId, await this.redis.hgetall(identityKey(aceId)));
  }

  /** The anti-rollback horizon of an identity unregistered here, or null. */
  async readHorizon(aceId: string): Promise<Horizon | null> {
    identityKey(aceId); // validates the ACE ID
    const h = await this.redis.hgetall(HORIZON_KEY_PREFIX + aceId);
    if (h.retiredAt === undefined) return null;
    return {
      retiredAt: Number(h.retiredAt), epochSeq: Number(h.epochSeq), epochStartHash: h.epochStartHash, lastSeq: Number(h.lastSeq),
      lastHash: h.lastHash,
    };
  }

  /** Atomic ordered write of the identity (07 § Registration). */
  register(w: RegistrationWrite): Promise<RegistrationStatus> {
    return this.redis.registerIdentity(
      identityKey(w.aceId), DESCRIPTOR_KEY_PREFIX + w.aceId, HORIZON_KEY_PREFIX + w.aceId,
      JSON.stringify(w.kel), String(w.seq), w.lastHash, w.signingPublicKey, String(w.timestamp), w.requestDigest,
      w.expectedLastHash ?? '', w.expectedRequestDigest ?? '', w.network, ...budgetArgs(this.budget),
    );
  }

  /**
   * Requires `signedTimestamp` > the stored registeredAt. Deletes queue, descriptor document, handle, blocks and wake in one
   * script; the KEL and a retiredAt barrier remain for OFFLINE_WINDOW_SECONDS, the horizon (`epoch`: the KEL's last
   * root epoch event and its last seq; its last hash is `expectedLastHash`) forever.
   */
  unregister(aceId: string, signedTimestamp: number, expectedLastHash: string, expectedRequestDigest: string,
    epoch: { epochSeq: number; epochStartHash: string; lastSeq: number }): Promise<UnregisterStatus> {
    return this.redis.unregisterIdentity(
      identityKey(aceId), DESCRIPTOR_KEY_PREFIX + aceId, DIRECTORY_KEY, BLOCKS_KEY_PREFIX + aceId, ...queueKeys(aceId),
      HORIZON_KEY_PREFIX + aceId,
      String(signedTimestamp), aceId, expectedLastHash, expectedRequestDigest, ...budgetArgs(this.budget),
      String(epoch.epochSeq), epoch.epochStartHash, String(epoch.lastSeq),
    );
  }
}
