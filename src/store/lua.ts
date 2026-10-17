import { REGNET_KEY_PREFIX, REGNET_STORED_KEY_PREFIX } from './keyspace.js';

/**
 * Every writing script starts with one of these shebangs. A script that may grow the store is refused whole by Redis
 * while the store is out of memory (never half-run, as a flagless script would be at its first denied write). Only a
 * script that frees memory or rewrites existing keys in place (ack, queue purge, unregister, changing an existing
 * block) runs regardless; one that writes a new small control key on a path needed to drain the store (the auth nonce
 * of a draining request, a per-client-network rate counter) runs regardless only within FULL_STORE_RESERVE_BYTES past
 * maxmemory (`withinReserve`).
 */
export const MAY_GROW = '#!lua\n';
export const RUNS_WHEN_FULL = '#!lua flags=allow-oom\n';

/**
 * How far past the store's maxmemory a RUNS_WHEN_FULL script may still add a small control key (a nonce, a rate
 * counter): a deliberately small, explicit reserve so a full store can still be drained, and no further.
 */
export const FULL_STORE_RESERVE_BYTES = 1024 * 1024;

/**
 * `atCapacity(highWater)`: the store's used memory (every relay key — identities, KELs, descriptors, horizons, queues,
 * control keys — plus the server's own overhead) is at or over the high-water mark. Growth stops there, below the
 * store's maxmemory, so control writes keep their reserve (07 § Send: refuse before the store is exhausted).
 * `withinReserve(reserve)`: used memory is below maxmemory + reserve (always true without a maxmemory).
 */
export const CAPACITY_LUA = `
local function memoryInfo()
  local info = '\\n' .. redis.call('INFO', 'memory')
  return tonumber(string.match(info, '\\nused_memory:(%d+)')), tonumber(string.match(info, '\\nmaxmemory:(%d+)') or '0')
end
local function atCapacity(highWater)
  local used = memoryInfo()
  return used >= highWater
end
local function withinReserve(reserve)
  local used, max = memoryInfo()
  return max == 0 or used < max + reserve
end
`;

/** `isActive(key)`: the identity hash holds a live registration (a signing key and no retiredAt barrier). */
export const IDENTITY_LUA = `
local function isActive(key)
  return redis.call('HEXISTS', key, 'signingPublicKey') == 1 and redis.call('HEXISTS', key, 'retiredAt') == 0
end
`;

/**
 * A client network's byte budget (07 § Registration, § Send) and the relay-wide high-water mark, as the scripts take
 * them: ARGV strings in this order (see `budgetArgs`). `bucketSeconds` and `ttlSeconds` are the packet window of the
 * bucketed hashes.
 */
export interface ByteBudget {
  bucketSeconds: number;
  ttlSeconds: number;
  networkBytes: number;
  trustedNetworkBytes: number;
  highWaterBytes: number;
}

export const budgetArgs = (b: ByteBudget): string[] =>
  [String(b.bucketSeconds), String(b.ttlSeconds), String(b.networkBytes), String(b.trustedNetworkBytes), String(b.highWaterBytes)];

/**
 * Byte accounting of bucketed hashes (field = bucket index, value = retained bytes): the `regnet:<rn>` hashes and a
 * queue meta's `g:<bucket>` mirror. Shared by the queue scripts and unregister.
 */
export const BYTES_LUA = `
local function decr(key, field, by)
  if redis.call('HEXISTS', key, field) == 1 and redis.call('HINCRBY', key, field, -by) <= 0 then redis.call('HDEL', key, field) end
end
-- The registration-network hash of rn (derived key, see keyspace), or nil.
local function regnetKey(rn)
  if rn then return '${REGNET_KEY_PREFIX}' .. rn end
  return nil
end
-- Live bytes of a bucketed hash (buckets after bucket - live); stale buckets are deleted on the way.
local function liveSum(key, bucket, live)
  local sum = 0
  local flat = redis.call('HGETALL', key)
  for i = 1, #flat, 2 do
    local idx = tonumber(flat[i])
    if idx == nil or idx <= bucket - live then redis.call('HDEL', key, flat[i]) else sum = sum + tonumber(flat[i + 1]) end
  end
  return sum
end
-- The stored (KEL and descriptor) bytes of rn's active identities: a plain counter, no expiry.
local function storedKey(rn) return '${REGNET_STORED_KEY_PREFIX}' .. rn end
local function charge(rn, by)
  if rn and by ~= 0 and redis.call('INCRBY', storedKey(rn), by) <= 0 then redis.call('DEL', storedKey(rn)) end
end
-- The current bucket index and the number of live buckets of a width/ttl packet window.
local function window(width, ttl)
  local t = redis.call('TIME')
  return math.floor(tonumber(t[1]) / width), math.ceil(ttl / width) + 1
end
-- What rn holds against its budget: live bucketed bytes (queued packets, retired KELs) plus stored bytes.
local function networkBytes(rn, bucket, live)
  return liveSum(regnetKey(rn), bucket, live) + tonumber(redis.call('GET', storedKey(rn)) or '0')
end
local function budgetOf(rn, budget, trusted)
  if string.sub(rn, 1, 2) == 't:' then return trusted end
  return budget
end
-- Whether rn cannot take delta more bytes (width, ttl, budget, trusted: the ByteBudget ARGV, as numbers).
local function overBudget(rn, delta, width, ttl, budget, trusted)
  if delta <= 0 then return false end
  local bucket, live = window(width, ttl)
  return networkBytes(rn, bucket, live) + delta > budgetOf(rn, budget, trusted)
end
-- Moves n stored bytes of rn into the current bucket, where they lapse with the packet window.
local function retire(rn, n, width, ttl)
  if not rn or n <= 0 then return end
  charge(rn, -n)
  redis.call('HINCRBY', regnetKey(rn), tostring(window(width, ttl)), n)
  redis.call('EXPIRE', regnetKey(rn), ttl + 2 * width)
end
-- Releases every g:<bucket> of a queue meta hash from the queue's registration network.
local function releaseQueue(metaKey)
  local rk = regnetKey(redis.call('HGET', metaKey, 'rn'))
  if not rk then return end
  local meta = redis.call('HGETALL', metaKey)
  for i = 1, #meta, 2 do
    local bucket = string.match(meta[i], '^g:(.+)$')
    if bucket then decr(rk, bucket, tonumber(meta[i + 1])) end
  end
end
`;
