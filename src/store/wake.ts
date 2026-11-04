import type Redis from 'ioredis';
import { OFFLINE_WINDOW_SECONDS } from '@ace-protocol/sdk';
import { IDENTITY_KEY_PREFIX, WAKE_KEY_PREFIX } from './keyspace.js';
import { BYTES_LUA, CAPACITY_LUA, IDENTITY_LUA, MAY_GROW, RUNS_WHEN_FULL, budgetArgs, type ByteBudget } from './lua.js';

/**
 * Bytes a wake registration is charged to its owner's registration network: an upper bound of its stored size (a
 * 2048-character gateway and a 512-character token). Charged once per registration (the identity's `wb`), kept while
 * the registration lapses by expiry, released by DELETE, a gone token and unregister.
 */
export const WAKE_BYTES = 3072;

export type WakeSetStatus = 'ok' | 'not_registered' | 'identity_conflict' | 'rate_limited' | 'relay_busy';

/**
 * KEYS: wake hash, identity hash. ARGV: gateway, token, expected lastHash, ttl, then the ByteBudget. Replaces the
 * registration armed; a first registration is charged WAKE_BYTES (`rate_limited` over the budget, refused at the
 * high-water mark).
 */
const SET_WAKE_SCRIPT = MAY_GROW + IDENTITY_LUA + BYTES_LUA + CAPACITY_LUA + `
local refused = checkOwner(KEYS[2], ARGV[3])
if refused then return refused end
if redis.call('HEXISTS', KEYS[2], 'wb') == 0 then
  local rn = redis.call('HGET', KEYS[2], 'regnet')
  if rn and overBudget(rn, ${WAKE_BYTES}, tonumber(ARGV[5]), tonumber(ARGV[6]), tonumber(ARGV[7]), tonumber(ARGV[8])) then return 'rate_limited' end
  if atCapacity(tonumber(ARGV[9])) then return 'relay_busy' end
  redis.call('HSET', KEYS[2], 'wb', ${WAKE_BYTES})
  charge(rn, ${WAKE_BYTES})
end
redis.call('HSET', KEYS[1], 'g', ARGV[1], 't', ARGV[2], 'a', '1')
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[4]))
return 'ok'
`;

/**
 * KEYS: wake hash, identity hash. ARGV: token or ''. Deletes the registration (only while it holds `token`, when
 * given) and releases its charge.
 */
const CLEAR_WAKE_SCRIPT = RUNS_WHEN_FULL + BYTES_LUA + `
if ARGV[1] ~= '' and redis.call('HGET', KEYS[1], 't') ~= ARGV[1] then return end
redis.call('DEL', KEYS[1])
local wb = tonumber(redis.call('HGET', KEYS[2], 'wb') or '0')
if wb > 0 then
  charge(redis.call('HGET', KEYS[2], 'regnet'), -wb)
  redis.call('HDEL', KEYS[2], 'wb')
end
`;

/** KEYS: wake hash. ARGV: ttl. Re-arms an existing registration and restarts its expiry (in place). */
const REARM_WAKE_SCRIPT = RUNS_WHEN_FULL + `
if redis.call('EXISTS', KEYS[1]) == 0 then return end
if redis.call('HGET', KEYS[1], 'a') ~= '1' then redis.call('HSET', KEYS[1], 'a', '1') end
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[1]))
`;

/**
 * KEYS: wake hash. ARGV: now ms, minimum interval ms. An armed registration whose last wake is at least the interval
 * ago is disarmed and returned as {'wake', gateway, token}; one due later {'defer', ms}; otherwise nil.
 */
const TAKE_WAKE_SCRIPT = RUNS_WHEN_FULL + `
local h = redis.call('HMGET', KEYS[1], 'g', 't', 'a', 'w')
if not h[1] or h[3] ~= '1' then return nil end
local due = tonumber(h[4] or '0') + tonumber(ARGV[2])
if tonumber(ARGV[1]) < due then return {'defer', tostring(due - tonumber(ARGV[1]))} end
redis.call('HSET', KEYS[1], 'a', '0', 'w', ARGV[1])
return {'wake', h[1], h[2]}
`;

type ScriptRedis = Redis & {
  setWake(...keysAndArgs: string[]): Promise<WakeSetStatus>;
  clearWake(...keysAndArgs: string[]): Promise<null>;
  rearmWake(...keysAndArgs: string[]): Promise<null>;
  takeWake(...keysAndArgs: string[]): Promise<[string, string, string?] | null>;
};

/** One wake registration per identity (07 § Wake hints) and its arming. */
export class WakeStore {
  private readonly redis: ScriptRedis;

  constructor(redis: Redis, private readonly budget: ByteBudget) {
    this.redis = redis as ScriptRedis;
    this.redis.defineCommand('setWake', { numberOfKeys: 2, lua: SET_WAKE_SCRIPT });
    this.redis.defineCommand('clearWake', { numberOfKeys: 2, lua: CLEAR_WAKE_SCRIPT });
    this.redis.defineCommand('rearmWake', { numberOfKeys: 1, lua: REARM_WAKE_SCRIPT });
    this.redis.defineCommand('takeWake', { numberOfKeys: 1, lua: TAKE_WAKE_SCRIPT });
  }

  set(owner: string, gateway: string, token: string, lastHash: string): Promise<WakeSetStatus> {
    return this.redis.setWake(WAKE_KEY_PREFIX + owner, IDENTITY_KEY_PREFIX + owner, gateway, token, lastHash,
      String(OFFLINE_WINDOW_SECONDS), ...budgetArgs(this.budget));
  }

  /** Removes the registration; with `token`, only while it still holds that token (a gateway's 404/410). */
  async clear(owner: string, token = ''): Promise<void> {
    await this.redis.clearWake(WAKE_KEY_PREFIX + owner, IDENTITY_KEY_PREFIX + owner, token);
  }

  /** An authenticated inbox, inbox-ack or listen request: re-arm and restart the expiry. */
  async rearm(owner: string): Promise<void> {
    await this.redis.rearmWake(WAKE_KEY_PREFIX + owner, String(OFFLINE_WINDOW_SECONDS));
  }

  /** Disarms an armed registration that is due: `wake`; one due later: `deferMs`; otherwise null. */
  async take(owner: string, nowMs: number, minIntervalMs: number): Promise<{ wake: { gateway: string; token: string } } | { deferMs: number } | null> {
    const r = await this.redis.takeWake(WAKE_KEY_PREFIX + owner, String(nowMs), String(minIntervalMs));
    if (r === null) return null;
    return r[0] === 'wake' ? { wake: { gateway: r[1], token: r[2]! } } : { deferMs: Number(r[1]) };
  }
}
