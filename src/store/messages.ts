import type Redis from 'ioredis';
import {
  CONTACT_REQUEST_TTL_SECONDS, MAX_PAGE_BYTES, STRANGER_ALLOWANCE, STRANGER_NETWORK_ALLOWANCE, compareStreamIds,
} from '@ace-protocol/sdk';
import { IDENTITY_KEY_PREFIX, queueKeys } from './keyspace.js';
import { BYTES_LUA, CAPACITY_LUA, IDENTITY_LUA, MAY_GROW, RUNS_WHEN_FULL, type ByteBudget } from './lua.js';

export interface StreamEntry {
  streamId: string;
  /** The stored packet JSON. */
  json: string;
}

export type EnqueueStatus =
  | 'duplicate' | 'unknown_peer' | 'recipient_inbox_full'
  /** The sender's network already holds its share of the recipient's stranger allowance. */
  | 'network_slots_full'
  /** The sender's share of the recipient's normal queue is full. */
  | 'sender_share_full'
  /** The recipient's registration network holds its byte budget. */
  | 'registration_network_full'
  /** The store's used memory is at the relay-wide high-water mark (last resort before the store is exhausted). */
  | 'relay_busy';

export type EnqueueResult = { status: 'enqueued'; streamId: string } | { status: EnqueueStatus };

export interface QueueLimits {
  /** Normal queue retention (seconds). */
  messageTtlSeconds: number;
  maxInboxEntries: number;
  maxInboxBytes: number;
  maxInboxSenderBytes: number;
  storageHighWaterBytes: number;
  registrationNetworkBytes: number;
  trustedRegistrationNetworkBytes: number;
}

/** `from` of the packet and the client network (used for stranger slots only). */
export interface EnqueueOrigin {
  sender: string;
  network: string;
}

/** Page bytes counted per entry beyond its packet (the inbox and listen framing). */
const PAGE_ENTRY_OVERHEAD = 64;

/**
 * Width of a byte-accounting bucket of the registration-network counters: at least an hour, at most ~25 buckets per
 * retention window. A counter forgets a bucket once every entry admitted in it is past retention, so bytes of a queue
 * that expired as a whole (key TTL) leave it without any script seeing them.
 */
export function bucketSeconds(ttlSeconds: number): number {
  return Math.max(3600, Math.ceil(ttlSeconds / 24));
}

/**
 * Shared by every queue script. KEYS[1..4] = inbox stream, meta hash, dedup hash (digest → stream ID), stranger zset
 * (stream ID by expiry ms). Entry fields: json, n (bytes), k ('n' normal
 * | 's' stranger), d (digest), b (accounting bucket), f (normal entry's sender), c (stranger's client network). Normal entries expire in stream
 * order (one retention); stranger entries by their zset score. Each entry is dropped once, releasing its counters,
 * dedup slot and retained bytes.
 */
const QUEUE_LIB = BYTES_LUA + `
local function drop(id, fields)
  local n, k, d, b, c, from = 0, 'n', nil, nil, nil, nil
  for i = 1, #fields, 2 do
    local f, v = fields[i], fields[i + 1]
    if f == 'n' then n = tonumber(v) elseif f == 'k' then k = v elseif f == 'd' then d = v elseif f == 'b' then b = v
    elseif f == 'c' then c = v elseif f == 'f' then from = v end
  end
  redis.call('XDEL', KEYS[1], id)
  if k == 's' then
    redis.call('HINCRBY', KEYS[2], 'sn', -1)
    redis.call('ZREM', KEYS[4], id)
    if c then decr(KEYS[2], 'sc:' .. c, 1) end
  else
    redis.call('HINCRBY', KEYS[2], 'nn', -1)
    redis.call('HINCRBY', KEYS[2], 'nb', -n)
    if from then decr(KEYS[2], 'fb:' .. from, n) end
  end
  if b then
    decr(KEYS[2], 'g:' .. b, n)
    local rk = regnetKey(redis.call('HGET', KEYS[2], 'rn'))
    if rk then decr(rk, b, n) end
  end
  if d and redis.call('HGET', KEYS[3], d) == id then redis.call('HDEL', KEYS[3], d) end
end
local function nowMs()
  local t = redis.call('TIME')
  return tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
end
-- Drops expired entries: normal ones older than ttlSeconds, stranger ones past their expiry. Bounded per call.
local function purge(now, ttlSeconds)
  for _, e in ipairs(redis.call('XRANGE', KEYS[1], '-', '(' .. tostring(now - ttlSeconds * 1000) .. '-0', 'COUNT', 256)) do drop(e[1], e[2]) end
  for _, id in ipairs(redis.call('ZRANGEBYSCORE', KEYS[4], '-inf', now, 'LIMIT', 0, 64)) do
    local e = redis.call('XRANGE', KEYS[1], id, id)
    if #e > 0 then drop(e[1][1], e[1][2]) else redis.call('ZREM', KEYS[4], id) end
  end
end
`;

/**
 * KEYS: 4 queue keys, identity hash. ARGV: json, digest, size, kind ('n' | 's'), normal ttl s, max normal entries, max
 * normal bytes, stranger ttl s, max stranger entries, bucket s, sender, max normal bytes per sender, high-water mark,
 * network, stranger entries per network, registration-network budget, trusted registration-network budget.
 *
 * Storage is charged to the recipient: its queue bounds (and a per-sender share of them, meta fb:<from>) are the
 * budget. The relay-wide high-water mark on the store's used memory is only the last resort.
 */
const ENQUEUE_SCRIPT = MAY_GROW + QUEUE_LIB + IDENTITY_LUA + CAPACITY_LUA + `
if not isActive(KEYS[5]) then return {'unknown_peer'} end
local now = nowMs()
local ttl = tonumber(ARGV[5])
purge(now, ttl)
local queued = redis.call('HGET', KEYS[3], ARGV[2])
if queued and #redis.call('XRANGE', KEYS[1], queued, queued) > 0 then return {'duplicate'} end
local size = tonumber(ARGV[3])
local net, from = ARGV[14], ARGV[11]
if ARGV[4] == 's' then
  if tonumber(redis.call('HGET', KEYS[2], 'sn') or '0') >= tonumber(ARGV[9]) then return {'recipient_inbox_full'} end
  if tonumber(redis.call('HGET', KEYS[2], 'sc:' .. net) or '0') >= tonumber(ARGV[15]) then return {'network_slots_full'} end
else
  if tonumber(redis.call('HGET', KEYS[2], 'nn') or '0') >= tonumber(ARGV[6])
    or tonumber(redis.call('HGET', KEYS[2], 'nb') or '0') + size > tonumber(ARGV[7]) then return {'recipient_inbox_full'} end
  if tonumber(redis.call('HGET', KEYS[2], 'fb:' .. from) or '0') + size > tonumber(ARGV[12]) then return {'sender_share_full'} end
end
local width = tonumber(ARGV[10])
local bucket = math.floor(now / 1000 / width)
local live = math.ceil(ttl / width) + 1
-- The recipient's registration network: attribute the queue's bytes to it (moving them after a re-registration from
-- another network), then hold it to its budget.
local rn = redis.call('HGET', KEYS[5], 'regnet')
local rkey = nil
if rn then
  rkey = regnetKey(rn)
  local old = redis.call('HGET', KEYS[2], 'rn')
  if old ~= rn then
    local meta = redis.call('HGETALL', KEYS[2])
    for i = 1, #meta, 2 do
      local g = string.match(meta[i], '^g:(.+)$')
      if g then
        if old then decr(regnetKey(old), g, tonumber(meta[i + 1])) end
        redis.call('HINCRBY', rkey, g, tonumber(meta[i + 1]))
      end
    end
    redis.call('HSET', KEYS[2], 'rn', rn)
    -- A refused send must not leave a fresh meta hash without the queue's lifetime.
    if redis.call('TTL', KEYS[2]) == -1 then redis.call('EXPIRE', KEYS[2], ttl) end
  end
  if networkBytes(rn, bucket, live) + size > budgetOf(rn, tonumber(ARGV[16]), tonumber(ARGV[17])) then return {'registration_network_full'} end
end
if atCapacity(tonumber(ARGV[13])) then return {'relay_busy'} end
local b = tostring(bucket)
local id
if ARGV[4] == 's' then
  id = redis.call('XADD', KEYS[1], '*', 'json', ARGV[1], 'n', ARGV[3], 'k', 's', 'd', ARGV[2], 'b', b, 'c', net)
  redis.call('HINCRBY', KEYS[2], 'sn', 1)
  redis.call('HINCRBY', KEYS[2], 'sc:' .. net, 1)
  redis.call('ZADD', KEYS[4], now + tonumber(ARGV[8]) * 1000, id)
else
  id = redis.call('XADD', KEYS[1], '*', 'json', ARGV[1], 'n', ARGV[3], 'k', 'n', 'd', ARGV[2], 'b', b, 'f', from)
  redis.call('HINCRBY', KEYS[2], 'nn', 1)
  redis.call('HINCRBY', KEYS[2], 'nb', size)
  redis.call('HINCRBY', KEYS[2], 'fb:' .. from, size)
end
redis.call('HSET', KEYS[3], ARGV[2], id)
redis.call('HINCRBY', KEYS[2], 'g:' .. b, size)
if rkey then
  redis.call('HINCRBY', rkey, b, size)
  redis.call('EXPIRE', rkey, ttl + 2 * width)
end
for i = 1, 4 do redis.call('EXPIRE', KEYS[i], ttl) end
return {'enqueued', id}
`;

/**
 * KEYS: 4 queue keys. ARGV: start ('-'-free XRANGE start), count, normal ttl s, page bytes. Purges, then reads at most
 * `count` entries and `page bytes` (each entry's n plus PAGE_ENTRY_OVERHEAD), at least one when any exists.
 */
const READ_SCRIPT = RUNS_WHEN_FULL + QUEUE_LIB + `
purge(nowMs(), tonumber(ARGV[3]))
local out = {}
local budget, bytes = tonumber(ARGV[4]), 0
for _, e in ipairs(redis.call('XRANGE', KEYS[1], ARGV[1], '+', 'COUNT', tonumber(ARGV[2]))) do
  local json, n
  for i = 1, #e[2], 2 do
    if e[2][i] == 'json' then json = e[2][i + 1] elseif e[2][i] == 'n' then n = tonumber(e[2][i + 1]) end
  end
  local size = n + ${PAGE_ENTRY_OVERHEAD}
  if #out > 0 and bytes + size > budget then break end
  bytes = bytes + size
  table.insert(out, {e[1], json})
end
return out
`;

/** ARGV: registration network, bucket s, normal ttl s. What the network holds against its budget. */
const NETWORK_BYTES_SCRIPT = RUNS_WHEN_FULL + BYTES_LUA + `
local bucket, live = window(tonumber(ARGV[2]), tonumber(ARGV[3]))
return networkBytes(ARGV[1], bucket, live)
`;

/** KEYS: 4 queue keys. ARGV: through. Deletes every entry up to and including `through`. */
const ACK_SCRIPT = RUNS_WHEN_FULL + QUEUE_LIB + `
local removed = 0
repeat
  local batch = redis.call('XRANGE', KEYS[1], '-', ARGV[1], 'COUNT', 256)
  for _, e in ipairs(batch) do drop(e[1], e[2]) end
  removed = removed + #batch
until #batch == 0
return removed
`;

type ScriptRedis = Redis & {
  enqueuePacket(...keysAndArgs: string[]): Promise<[string, string?]>;
  readQueue(...keysAndArgs: string[]): Promise<Array<[string, string]>>;
  ackQueue(...keysAndArgs: string[]): Promise<number>;
  networkBytes(network: string, bucketSeconds: string, ttlSeconds: string): Promise<number>;
};

/**
 * One stream per recipient holding opaque packets of both admission kinds (07 § Send): `normal` (with a permit)
 * retained messageTtlSeconds and bounded in entries and bytes; `stranger` (no permit) at most STRANGER_ALLOWANCE,
 * each retained CONTACT_REQUEST_TTL_SECONDS, at most STRANGER_NETWORK_ALLOWANCE of them per client network. Byte-identical packets
 * are queued once. Storage is charged to the recipient that authorized it (its queue bounds, with a per-sender share);
 * sends stop once the store's used memory reaches storageHighWaterBytes (see CAPACITY_LUA).
 */
export class MessageStore {
  private readonly redis: ScriptRedis;
  private readonly bucketSeconds: number;

  constructor(redis: Redis, private readonly limits: QueueLimits) {
    this.redis = redis as ScriptRedis;
    this.bucketSeconds = bucketSeconds(limits.messageTtlSeconds);
    this.redis.defineCommand('enqueuePacket', { numberOfKeys: 5, lua: ENQUEUE_SCRIPT });
    this.redis.defineCommand('readQueue', { numberOfKeys: 4, lua: READ_SCRIPT });
    this.redis.defineCommand('ackQueue', { numberOfKeys: 4, lua: ACK_SCRIPT });
    this.redis.defineCommand('networkBytes', { numberOfKeys: 0, lua: NETWORK_BYTES_SCRIPT });
  }

  /** The byte budget of a registration network and the high-water mark, as the identity and descriptor scripts take them. */
  get budget(): ByteBudget {
    const l = this.limits;
    return {
      bucketSeconds: this.bucketSeconds, ttlSeconds: l.messageTtlSeconds,
      networkBytes: l.registrationNetworkBytes, trustedNetworkBytes: l.trustedRegistrationNetworkBytes, highWaterBytes: l.storageHighWaterBytes,
    };
  }

  async enqueue(to: string, json: string, digest: string, kind: 'normal' | 'stranger', origin: EnqueueOrigin): Promise<EnqueueResult> {
    const l = this.limits;
    const [status, streamId] = await this.redis.enqueuePacket(
      ...queueKeys(to), IDENTITY_KEY_PREFIX + to,
      json, digest, String(Buffer.byteLength(json)), kind === 'stranger' ? 's' : 'n', String(l.messageTtlSeconds),
      String(l.maxInboxEntries), String(l.maxInboxBytes), String(CONTACT_REQUEST_TTL_SECONDS), String(STRANGER_ALLOWANCE),
      String(this.bucketSeconds), origin.sender, String(l.maxInboxSenderBytes),
      String(l.storageHighWaterBytes), origin.network, String(STRANGER_NETWORK_ALLOWANCE),
      String(l.registrationNetworkBytes), String(l.trustedRegistrationNetworkBytes),
    );
    if (status === 'enqueued') return { status, streamId: streamId! };
    return { status: status as EnqueueStatus };
  }

  /**
   * What a registration network (`n:<net>` or `t:<cidr>`) holds against its budget: queued packet bytes, the stored KEL
   * and descriptor bytes of its active identities, and the KELs of identities retired from it.
   */
  registrationNetworkBytes(network: string): Promise<number> {
    return this.redis.networkBytes(network, String(this.bucketSeconds), String(this.limits.messageTtlSeconds));
  }

  /** Whether a byte-identical packet (by digest) is queued for `to`. */
  async isQueued(to: string, digest: string): Promise<boolean> {
    const [inbox, , dedup] = queueKeys(to);
    const id = await this.redis.hget(dedup, digest);
    return id !== null && (await this.redis.xrange(inbox, id, id)).length > 0;
  }

  /**
   * Live entries strictly after `since` ('-' = from the start), oldest first: at most `limit`, at most MAX_PAGE_BYTES
   * of packets, and at least one entry when any exists.
   */
  async getMessages(aceId: string, since: string, limit: number): Promise<{ messages: StreamEntry[]; cursor: string | null }> {
    const floor = `${Math.max(0, Date.now() - this.limits.messageTtlSeconds * 1000)}-0`;
    const start = since === '-' || compareStreamIds(since, floor) < 0 ? floor : `(${since}`;
    const raw = await this.redis.readQueue(
      ...queueKeys(aceId), start, String(limit), String(this.limits.messageTtlSeconds), String(MAX_PAGE_BYTES),
    );
    const messages = raw.map(([streamId, json]): StreamEntry => ({ streamId, json }));
    return { messages, cursor: messages.at(-1)?.streamId ?? null };
  }

  /** Deletes `aceId`'s entries up to and including `through`; idempotent. Returns how many were removed. */
  ack(aceId: string, through: string): Promise<number> {
    return this.redis.ackQueue(...queueKeys(aceId), through);
  }
}
