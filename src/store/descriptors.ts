import type Redis from 'ioredis';
import { MAX_PAGE_BYTES, type PublishedAgent } from '@ace-protocol/sdk';
import { CARD_KEY_PREFIX, DESCRIPTOR_KEY_PREFIX, DIRECTORY_KEY, IDENTITY_KEY_PREFIX } from './keyspace.js';
import { BYTES_LUA, CAPACITY_LUA, IDENTITY_LUA, MAY_GROW, budgetArgs, type ByteBudget } from './lua.js';
import { StorageError } from '../errors.js';

export type PublishStatus = 'published' | 'not_registered' | 'kel_conflict' | 'stale_descriptor' | 'rate_limited' | 'relay_busy';

/**
 * KEYS: descriptor hash, identity hash. ARGV: aceId, issuedAt, claims digest, json, lastHash, expiresAt, profile ids
 * (space separated), then the ByteBudget. The json's bytes (jb) are charged to the network the identity registered from
 * (07 § Descriptors and cards); a larger document is refused while the store is at the relay-wide high-water mark
 * (`relay_busy`). The directory entry follows the card record (CardStore), not the descriptor.
 */
const PUBLISH_SCRIPT = MAY_GROW + IDENTITY_LUA + BYTES_LUA + CAPACITY_LUA + `
if not isActive(KEYS[2]) then return 'not_registered' end
if redis.call('HGET', KEYS[2], 'lastHash') ~= ARGV[5] then return 'kel_conflict' end
local at = tonumber(redis.call('HGET', KEYS[1], 'issuedAt') or '-1')
local issuedAt = tonumber(ARGV[2])
if at > issuedAt then return 'stale_descriptor' end
if at == issuedAt and redis.call('HGET', KEYS[1], 'digest') ~= ARGV[3] then return 'stale_descriptor' end
local rn = redis.call('HGET', KEYS[2], 'regnet')
local delta = #ARGV[4] - tonumber(redis.call('HGET', KEYS[1], 'jb') or '0')
if rn and overBudget(rn, delta, tonumber(ARGV[8]), tonumber(ARGV[9]), tonumber(ARGV[10]), tonumber(ARGV[11])) then return 'rate_limited' end
if delta > 0 and atCapacity(tonumber(ARGV[12])) then return 'relay_busy' end
charge(rn, delta)
redis.call('HSET', KEYS[1], 'issuedAt', ARGV[2], 'digest', ARGV[3], 'json', ARGV[4], 'lastHash', ARGV[5],
  'expiresAt', ARGV[6], 'profiles', ARGV[7], 'jb', #ARGV[4])
return 'published'
`;

type ScriptRedis = Redis & { publishDescriptor(...keysAndArgs: (string | number)[]): Promise<PublishStatus> };

const FIELDS = ['json', 'lastHash', 'expiresAt', 'profiles'] as const;
/** Directory entries one page may examine. */
const DIRECTORY_SCAN_BUDGET = 1000;
const DIRECTORY_BATCH = 200;

interface Row { json: string; profiles: string[]; listed: boolean }

/** Signed PublishedAgents and the directory of listed identities. Only complete signed documents are stored and served. */
export class DescriptorStore {
  private readonly redis: ScriptRedis;

  constructor(redis: Redis, private readonly budget: ByteBudget) {
    this.redis = redis as ScriptRedis;
    this.redis.defineCommand('publishDescriptor', { numberOfKeys: 2, lua: PUBLISH_SCRIPT });
  }

  publish(agent: PublishedAgent, lastHash: string, digest: string): Promise<PublishStatus> {
    const d = agent.descriptor;
    return this.redis.publishDescriptor(
      DESCRIPTOR_KEY_PREFIX + d.aceId, IDENTITY_KEY_PREFIX + d.aceId,
      d.aceId, d.issuedAt, digest, JSON.stringify(agent), lastHash, d.expiresAt, d.profiles.map((p) => p.id).join(' '),
      ...budgetArgs(this.budget),
    );
  }

  /** The stored, unexpired descriptor of an active identity whose KEL it carries. */
  async get(aceId: string, now: number): Promise<PublishedAgent | null> {
    const [row] = await this.rows([aceId], now);
    return row ? parse(aceId, row.json) : null;
  }

  /** Unexpired descriptors of listed identities ordered by ACE ID after `cursor`, optionally listing `profile`. */
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
        if (row && row.listed && (!profile || row.profiles.includes(profile))) {
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

  /** Rows of active identities whose stored descriptor carries their registered KEL and is unexpired, with whether their current card record is listed. */
  private async rows(ids: string[], now: number): Promise<Array<Row | null>> {
    if (ids.length === 0) return [];
    const pipe = this.redis.pipeline();
    for (const id of ids) {
      pipe.hmget(DESCRIPTOR_KEY_PREFIX + id, ...FIELDS);
      pipe.hmget(IDENTITY_KEY_PREFIX + id, 'lastHash', 'retiredAt');
      pipe.hmget(CARD_KEY_PREFIX + id, 'listed', 'lastHash');
    }
    const res = (await pipe.exec()) ?? [];
    return ids.map((_, i) => {
      const [e1, d] = res[3 * i] as [Error | null, (string | null)[]];
      const [e2, idn] = res[3 * i + 1] as [Error | null, (string | null)[]];
      const [e3, card] = res[3 * i + 2] as [Error | null, (string | null)[]];
      if (e1 || e2 || e3) throw e1 ?? e2 ?? e3;
      const [json, lastHash, expiresAt, profiles] = d;
      if (json === null || lastHash === null || idn[1] !== null || idn[0] !== lastHash || !(Number(expiresAt) > now)) return null;
      // Listed only by a record published under the current KEL (CardStore).
      return { json, profiles: (profiles ?? '').split(' ').filter(Boolean), listed: card[0] === '1' && card[1] === lastHash };
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
