import type Redis from 'ioredis';
import { RATE_KEY_PREFIX } from './keyspace.js';
import { CAPACITY_LUA, FULL_STORE_RESERVE_BYTES, MAY_GROW, RUNS_WHEN_FULL } from './lua.js';

/** INCR and the window's EXPIRE in one script, so a crash never leaves a counter without TTL. ARGV[1]: window s. */
const COUNT_LUA = `
local current = redis.call('INCR', KEYS[1])
if current == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
return {current, redis.call('TTL', KEYS[1])}
`;

/** A bucket keyed on something unbounded (an ACE ID): refused at the high-water mark (ARGV[2]) like any growth. */
const RATE_LIMIT_SCRIPT = MAY_GROW + CAPACITY_LUA + `
if atCapacity(tonumber(ARGV[2])) then return {-1, 0} end
` + COUNT_LUA;

/**
 * A bucket keyed on a client network (bounded by the client addresses that reach the relay): every /v1 request counts
 * one first, ack and unregister included, so it runs even when the store is full, within the reserve (ARGV[2]).
 */
const NETWORK_RATE_LIMIT_SCRIPT = RUNS_WHEN_FULL + CAPACITY_LUA + `
if not withinReserve(tonumber(ARGV[2])) then return {-1, 0} end
` + COUNT_LUA;

type ScriptRedis = Redis & {
  rateLimit(key: string, windowSeconds: number, highWaterBytes: number): Promise<[number, number]>;
  networkRateLimit(key: string, windowSeconds: number, reserveBytes: number): Promise<[number, number]>;
};

export type RateResult = { allowed: true } | { allowed: false; retryAfter: number } | { full: true };

export class RateLimiter {
  private readonly redis: ScriptRedis;
  constructor(redis: Redis, private readonly highWaterBytes: number) {
    this.redis = redis as ScriptRedis;
    this.redis.defineCommand('rateLimit', { numberOfKeys: 1, lua: RATE_LIMIT_SCRIPT });
    this.redis.defineCommand('networkRateLimit', { numberOfKeys: 1, lua: NETWORK_RATE_LIMIT_SCRIPT });
  }

  /**
   * Counts one event in `bucket`'s fixed window (under `ace:rate:`). `networkKeyed`: the bucket is keyed on a client
   * network. `full`: the store has no room for the counter (nothing counted).
   */
  async check(bucket: string, limit: number, windowSeconds: number, networkKeyed: boolean): Promise<RateResult> {
    const key = RATE_KEY_PREFIX + bucket;
    const [current, ttl] = networkKeyed
      ? await this.redis.networkRateLimit(key, windowSeconds, FULL_STORE_RESERVE_BYTES)
      : await this.redis.rateLimit(key, windowSeconds, this.highWaterBytes);
    if (current < 0) return { full: true };
    if (current > limit) return { allowed: false, retryAfter: ttl > 0 ? ttl : windowSeconds };
    return { allowed: true };
  }
}
