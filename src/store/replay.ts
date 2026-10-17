import type Redis from 'ioredis';
import { TIMESTAMP_WINDOW_SECONDS } from '@ace-protocol/sdk';
import { RelayError } from '../errors.js';
import { REPLAY_KEY_PREFIX } from './keyspace.js';
import { CAPACITY_LUA, FULL_STORE_RESERVE_BYTES, MAY_GROW, RUNS_WHEN_FULL } from './lua.js';

/** 07 § Authentication: a nonce is remembered for at least 2 · TIMESTAMP_WINDOW_SECONDS + 1 seconds. */
export const REPLAY_TTL_SECONDS = 2 * TIMESTAMP_WINDOW_SECONDS + 1;

/** 07 § Authentication: 32 random bytes as 64 lowercase hex. Bounds the key the store writes. */
const NONCE_PATTERN = /^[0-9a-f]{64}$/;

/** KEYS: nonce key. ARGV: ttl s. A new key: an ordinary growing write, refused while the store is out of memory. */
const CONSUME_SCRIPT = MAY_GROW + `return redis.call('SET', KEYS[1], '1', 'EX', ARGV[1], 'NX') and 'ok' or 'replay'`;

/**
 * KEYS: nonce key. ARGV: ttl s, reserve bytes. The nonce of a request that drains the store (inbox read, ack, unregister,
 * unblock): written even when the store is full, but only within the reserve past maxmemory (`full` beyond it).
 */
const CONSUME_DRAINING_SCRIPT = RUNS_WHEN_FULL + CAPACITY_LUA + `
if not withinReserve(tonumber(ARGV[2])) then return 'full' end
return redis.call('SET', KEYS[1], '1', 'EX', ARGV[1], 'NX') and 'ok' or 'replay'
`;

export type ConsumeStatus = 'ok' | 'replay' | 'full';

type ScriptRedis = Redis & {
  consumeNonce(key: string, ttlSeconds: number): Promise<ConsumeStatus>;
  consumeDrainingNonce(key: string, ttlSeconds: number, reserveBytes: number): Promise<ConsumeStatus>;
};

export class ReplayStore {
  private readonly redis: ScriptRedis;
  constructor(redis: Redis) {
    this.redis = redis as ScriptRedis;
    this.redis.defineCommand('consumeNonce', { numberOfKeys: 1, lua: CONSUME_SCRIPT });
    this.redis.defineCommand('consumeDrainingNonce', { numberOfKeys: 1, lua: CONSUME_DRAINING_SCRIPT });
  }

  /**
   * `ok` the first time `(aceId, nonce)` is seen within REPLAY_TTL_SECONDS, then `replay`. `draining`: the request frees
   * memory, so its nonce may use the full-store reserve (`full` past it).
   */
  consume(aceId: string, nonce: string, draining: boolean): Promise<ConsumeStatus> {
    if (!NONCE_PATTERN.test(nonce)) throw new RelayError('invalid_argument', 'nonce must be 64 lowercase hex');
    const key = `${REPLAY_KEY_PREFIX}${aceId}:${nonce}`;
    return draining
      ? this.redis.consumeDrainingNonce(key, REPLAY_TTL_SECONDS, FULL_STORE_RESERVE_BYTES)
      : this.redis.consumeNonce(key, REPLAY_TTL_SECONDS);
  }
}
