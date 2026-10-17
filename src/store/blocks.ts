import type Redis from 'ioredis';
import { MIN_BLOCK_CAP } from '@ace-protocol/sdk';
import { BLOCKS_KEY_PREFIX, IDENTITY_KEY_PREFIX } from './keyspace.js';
import { BYTES_LUA, CAPACITY_LUA, IDENTITY_LUA, MAY_GROW, RUNS_WHEN_FULL, budgetArgs, type ByteBudget } from './lua.js';

/** Tracked block records per identity (07 § Blocks: at least MIN_BLOCK_CAP). */
const MAX_BLOCKS_PER_IDENTITY = 4 * MIN_BLOCK_CAP;

/** Bytes one block record is charged to its owner's registration network: an upper bound of its stored size. */
export const BLOCK_BYTES = 256;

export type BlockStatus = 'ok' | 'not_registered' | 'identity_conflict' | 'stale_revision' | 'limit_exceeded' | 'rate_limited' | 'relay_busy';

/** Values are "<revision>:<0|1>"; the revision is kept after an unblock (07 § Blocks). */
const BLOCK_LUA = IDENTITY_LUA + `
-- Rewrites an existing record in place; nil when there is none.
local function update(old)
  if tonumber(string.match(old, '^(%d+):')) >= tonumber(ARGV[2]) then return 'stale_revision' end
  redis.call('HSET', KEYS[1], ARGV[1], ARGV[2] .. ':' .. ARGV[3])
  return 'ok'
end
`;

/**
 * KEYS: blocks hash, identity hash. ARGV: peer, revision, '1' | '0', expected lastHash. Changes an existing record in
 * place (no growth), so it runs even when the store is full; `absent` when the peer has no record yet.
 */
const UPDATE_BLOCK_SCRIPT = RUNS_WHEN_FULL + BLOCK_LUA + `
local refused = checkOwner(KEYS[2], ARGV[4])
if refused then return refused end
local old = redis.call('HGET', KEYS[1], ARGV[1])
if not old then return 'absent' end
return update(old)
`;

/**
 * KEYS: blocks hash, identity hash. ARGV: peer, revision, '1' | '0', expected lastHash, cap, then the ByteBudget. A new
 * record grows the store: bounded by the cap, charged BLOCK_BYTES to the owner's registration network (`rate_limited`
 * over its budget; tracked as the identity's `bb` and released at unregister) and refused at the high-water mark.
 */
const INSERT_BLOCK_SCRIPT = MAY_GROW + BLOCK_LUA + BYTES_LUA + CAPACITY_LUA + `
local refused = checkOwner(KEYS[2], ARGV[4])
if refused then return refused end
local old = redis.call('HGET', KEYS[1], ARGV[1])
if old then return update(old) end
if redis.call('HLEN', KEYS[1]) >= tonumber(ARGV[5]) then return 'limit_exceeded' end
local rn = redis.call('HGET', KEYS[2], 'regnet')
if rn and overBudget(rn, ${BLOCK_BYTES}, tonumber(ARGV[6]), tonumber(ARGV[7]), tonumber(ARGV[8]), tonumber(ARGV[9])) then return 'rate_limited' end
if atCapacity(tonumber(ARGV[10])) then return 'relay_busy' end
redis.call('HSET', KEYS[1], ARGV[1], ARGV[2] .. ':' .. ARGV[3])
redis.call('HINCRBY', KEYS[2], 'bb', ${BLOCK_BYTES})
charge(rn, ${BLOCK_BYTES})
return 'ok'
`;

type ScriptRedis = Redis & {
  updateBlock(...keysAndArgs: string[]): Promise<BlockStatus | 'absent'>;
  insertBlock(...keysAndArgs: string[]): Promise<BlockStatus>;
};

/** Signed blocks per identity: `(owner, peer) → {revision, blocked}`. */
export class BlockStore {
  private readonly redis: ScriptRedis;

  constructor(redis: Redis, private readonly budget: ByteBudget) {
    this.redis = redis as ScriptRedis;
    this.redis.defineCommand('updateBlock', { numberOfKeys: 2, lua: UPDATE_BLOCK_SCRIPT });
    this.redis.defineCommand('insertBlock', { numberOfKeys: 2, lua: INSERT_BLOCK_SCRIPT });
  }

  async set(owner: string, peer: string, blocked: boolean, revision: number, lastHash: string): Promise<BlockStatus> {
    const keysAndArgs = [BLOCKS_KEY_PREFIX + owner, IDENTITY_KEY_PREFIX + owner, peer, String(revision), blocked ? '1' : '0', lastHash];
    const status = await this.redis.updateBlock(...keysAndArgs);
    if (status !== 'absent') return status;
    return this.redis.insertBlock(...keysAndArgs, String(MAX_BLOCKS_PER_IDENTITY), ...budgetArgs(this.budget));
  }

  /** Whether `owner` currently blocks `peer`. */
  async isBlocked(owner: string, peer: string): Promise<boolean> {
    return (await this.redis.hget(BLOCKS_KEY_PREFIX + owner, peer))?.endsWith(':1') ?? false;
  }
}
