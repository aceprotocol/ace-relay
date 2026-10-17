import type Redis from 'ioredis';
import { MAX_PAGE_BYTES, type PublishedAgent } from '@ace-protocol/sdk';
import { DESCRIPTOR_KEY_PREFIX, DIRECTORY_KEY, HANDLE_KEY_PREFIX, IDENTITY_KEY_PREFIX, handleKey } from './keyspace.js';
import { BYTES_LUA, CAPACITY_LUA, IDENTITY_LUA, MAY_GROW, budgetArgs, type ByteBudget } from './lua.js';
import { StorageError } from '../errors.js';

export type PublishStatus = 'published' | 'not_registered' | 'kel_conflict' | 'stale_descriptor' | 'handle_taken' | 'rate_limited' | 'relay_busy';

/**
 * KEYS: descriptor hash, directory zset, identity hash, new handle key.
 * ARGV: aceId, issuedAt, claims digest, json, handle ttl, lastHash, visibility, new handle, expiresAt, profile ids
 * (space separated), then the ByteBudget. The previous handle's key is derived from the stored descriptor (see
 * keyspace). The json's bytes (jb) are charged to the network the identity registered from (07 § Descriptors); a larger
 * document is refused while the store is at the relay-wide high-water mark (`relay_busy`).
 */
const PUBLISH_SCRIPT = MAY_GROW + IDENTITY_LUA + BYTES_LUA + CAPACITY_LUA + `
if not isActive(KEYS[3]) then return 'not_registered' end
if redis.call('HGET', KEYS[3], 'lastHash') ~= ARGV[6] then return 'kel_conflict' end
local previous = redis.call('HGET', KEYS[1], 'handle') or ''
local at = tonumber(redis.call('HGET', KEYS[1], 'issuedAt') or '-1')
local issuedAt = tonumber(ARGV[2])
if at > issuedAt then return 'stale_descriptor' end
if at == issuedAt and redis.call('HGET', KEYS[1], 'digest') ~= ARGV[3] then return 'stale_descriptor' end
if ARGV[8] ~= '' then
  local owner = redis.call('GET', KEYS[4])
  if owner and owner ~= ARGV[1] then return 'handle_taken' end
end
local rn = redis.call('HGET', KEYS[3], 'regnet')
local delta = #ARGV[4] - tonumber(redis.call('HGET', KEYS[1], 'jb') or '0')
if rn and overBudget(rn, delta, tonumber(ARGV[11]), tonumber(ARGV[12]), tonumber(ARGV[13]), tonumber(ARGV[14])) then return 'rate_limited' end
if delta > 0 and atCapacity(tonumber(ARGV[15])) then return 'relay_busy' end
charge(rn, delta)
local previousKey = '${HANDLE_KEY_PREFIX}' .. previous
if previous ~= '' and previous ~= ARGV[8] and redis.call('GET', previousKey) == ARGV[1] then redis.call('DEL', previousKey) end
if ARGV[8] ~= '' then redis.call('SET', KEYS[4], ARGV[1], 'EX', ARGV[5]) end
redis.call('HSET', KEYS[1], 'issuedAt', ARGV[2], 'digest', ARGV[3], 'json', ARGV[4], 'lastHash', ARGV[6],
  'handle', ARGV[8], 'visibility', ARGV[7], 'expiresAt', ARGV[9], 'profiles', ARGV[10], 'jb', #ARGV[4])
if ARGV[7] == 'public' then redis.call('ZADD', KEYS[2], 0, ARGV[1]) else redis.call('ZREM', KEYS[2], ARGV[1]) end
return 'published'
`;

type ScriptRedis = Redis & { publishDescriptor(...keysAndArgs: (string | number)[]): Promise<PublishStatus> };

const FIELDS = ['json', 'lastHash', 'expiresAt', 'visibility', 'profiles'] as const;
/** Directory entries one page may examine. */
const DIRECTORY_SCAN_BUDGET = 1000;
const DIRECTORY_BATCH = 200;

interface Row { json: string; visibility: string; profiles: string[] }

/** Signed PublishedAgents, the public directory and handles. Only complete signed documents are stored and served. */
export class DescriptorStore {
  private readonly redis: ScriptRedis;

  constructor(redis: Redis, private readonly budget: ByteBudget) {
    this.redis = redis as ScriptRedis;
    this.redis.defineCommand('publishDescriptor', { numberOfKeys: 4, lua: PUBLISH_SCRIPT });
  }

  /** `handle` is the handle to claim here ('' when none: not public, no handle, or this relay is not `relays[0]`). */
  publish(agent: PublishedAgent, lastHash: string, digest: string, handle: string, now: number): Promise<PublishStatus> {
    const d = agent.descriptor;
    return this.redis.publishDescriptor(
      DESCRIPTOR_KEY_PREFIX + d.aceId, DIRECTORY_KEY, IDENTITY_KEY_PREFIX + d.aceId, handleKey(handle),
      d.aceId, d.issuedAt, digest, JSON.stringify(agent), Math.max(1, d.expiresAt - now), lastHash, d.visibility,
      handle, d.expiresAt, d.profiles.map((p) => p.id).join(' '), ...budgetArgs(this.budget),
    );
  }

  /** The stored, unexpired descriptor of an active identity whose KEL it carries; any visibility. */
  async get(aceId: string, now: number): Promise<PublishedAgent | null> {
    const [row] = await this.rows([aceId], now);
    return row ? parse(aceId, row.json) : null;
  }

  async resolveHandle(handle: string, now: number): Promise<PublishedAgent | null> {
    const owner = await this.redis.get(HANDLE_KEY_PREFIX + handle);
    if (owner === null) return null;
    const [row] = await this.rows([owner], now);
    if (!row || row.visibility !== 'public') return null;
    const agent = parse(owner, row.json);
    return agent.descriptor.handle === handle ? agent : null;
  }

  /** Public, unexpired descriptors ordered by ACE ID after `cursor`, optionally listing `profile`. */
  async discover(cursor: string | undefined, limit: number, profile: string | undefined, now: number): Promise<{ agents: PublishedAgent[]; cursor: string | null }> {
    const agents: PublishedAgent[] = [];
    let bytes = 0;
    let scanned = 0;
    let after = cursor;
    for (;;) {
      const ids = await this.redis.zrangebylex(DIRECTORY_KEY, after ? `(${after}` : '-', '+', 'LIMIT', 0, DIRECTORY_BATCH);
      const rows = await this.rows(ids, now);
      for (let i = 0; i < ids.length; i++) {
        const row = rows[i];
        if (row && row.visibility === 'public' && (!profile || row.profiles.includes(profile))) {
          const size = Buffer.byteLength(row.json) + 1;
          if (agents.length > 0 && bytes + size > MAX_PAGE_BYTES) return { agents, cursor: after ?? null };
          agents.push(parse(ids[i], row.json));
          bytes += size;
        }
        after = ids[i];
        scanned++;
        if (agents.length === limit || scanned === DIRECTORY_SCAN_BUDGET) {
          const more = i < ids.length - 1 || (await this.redis.zrangebylex(DIRECTORY_KEY, `(${after}`, '+', 'LIMIT', 0, 1)).length > 0;
          return { agents, cursor: more ? after : null };
        }
      }
      if (ids.length < DIRECTORY_BATCH) return { agents, cursor: null };
    }
  }

  /** Rows of active identities whose stored descriptor carries their registered KEL and is unexpired. */
  private async rows(ids: string[], now: number): Promise<Array<Row | null>> {
    if (ids.length === 0) return [];
    const pipe = this.redis.pipeline();
    for (const id of ids) {
      pipe.hmget(DESCRIPTOR_KEY_PREFIX + id, ...FIELDS);
      pipe.hmget(IDENTITY_KEY_PREFIX + id, 'lastHash', 'retiredAt');
    }
    const res = (await pipe.exec()) ?? [];
    return ids.map((_, i) => {
      const [e1, d] = res[2 * i] as [Error | null, (string | null)[]];
      const [e2, idn] = res[2 * i + 1] as [Error | null, (string | null)[]];
      if (e1 || e2) throw e1 ?? e2;
      const [json, lastHash, expiresAt, visibility, profiles] = d;
      if (json === null || lastHash === null || idn[1] !== null || idn[0] !== lastHash || !(Number(expiresAt) > now)) return null;
      return { json, visibility: visibility ?? '', profiles: (profiles ?? '').split(' ').filter(Boolean) };
    });
  }
}

function parse(aceId: string, json: string): PublishedAgent {
  try {
    return JSON.parse(json) as PublishedAgent;
  } catch {
    throw new StorageError(`corrupt descriptor of ${aceId}`);
  }
}
