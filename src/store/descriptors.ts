import type Redis from 'ioredis';
import { MAX_PAGE_BYTES, type PublishedAgent } from '@ace-protocol/sdk';
import { ACTIVE_FIELDS, CARD_KEY_PREFIX, DESCRIPTOR_KEY_PREFIX, DIRECTORY_KEY, IDENTITY_KEY_PREFIX, activeLastHash } from './keyspace.js';
import { BYTES_LUA, CAPACITY_LUA, DOCUMENT_LUA, IDENTITY_LUA, MAY_GROW, budgetArgs, type ByteBudget } from './lua.js';
import { parseStored } from '../errors.js';

export type PublishStatus = 'published' | 'not_registered' | 'kel_conflict' | 'stale_descriptor' | 'rate_limited' | 'relay_busy';

/**
 * KEYS: descriptor hash, identity hash. ARGV: aceId, issuedAt, claims digest, json, lastHash, expiresAt, profile ids
 * (space separated), then the ByteBudget. The json's bytes (jb) are charged to the network the identity registered from
 * (07 § Descriptors and cards); a larger document is refused while the store is at the relay-wide high-water mark
 * (`relay_busy`). The directory entry follows the card record (CardStore), not the descriptor. `issuedAt` must be newer than
 * the stored descriptor's (or equal with the same digest) only while that one carries the registered KEL (07 § Descriptors
 * and cards: a stored descriptor under another KEL is absent). A descriptor signed before its delegating `dlg` (e.g. under
 * the superseded branch of a fork recovery that re-delegated the same key at the same seq) is refused by verification
 * (`stale_peer_binding`, 04 § Verification step 3), not here.
 */
const PUBLISH_SCRIPT = MAY_GROW + IDENTITY_LUA + BYTES_LUA + CAPACITY_LUA + DOCUMENT_LUA + `
if not isActive(KEYS[2]) then return 'not_registered' end
if redis.call('HGET', KEYS[2], 'lastHash') ~= ARGV[5] then return 'kel_conflict' end
if isStale(KEYS[1], ARGV[5], ARGV[2], ARGV[3]) then return 'stale_descriptor' end
local refused = chargeDocument(KEYS[1], KEYS[2], ARGV[4], 8)
if refused then return refused end
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
    return row ? parseStored<PublishedAgent>(row.json, `descriptor of ${aceId}`) : null;
  }

  /**
   * Whether the stored descriptor carries `lastHash`, the registered KEL of an identity the caller read as active, and is
   * unexpired (see `get`), without reading the document.
   */
  async isLive(aceId: string, lastHash: string, now: number): Promise<boolean> {
    const [stored, expiresAt] = await this.redis.hmget(DESCRIPTOR_KEY_PREFIX + aceId, 'lastHash', 'expiresAt');
    return stored === lastHash && Number(expiresAt) > now;
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
          agents.push(parseStored<PublishedAgent>(row.json, `descriptor of ${ids[i]}`));
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
      pipe.hmget(IDENTITY_KEY_PREFIX + id, ...ACTIVE_FIELDS);
      pipe.hmget(CARD_KEY_PREFIX + id, 'listed', 'lastHash');
    }
    const res = (await pipe.exec()) ?? [];
    return ids.map((_, i) => {
      const [e1, d] = res[3 * i] as [Error | null, (string | null)[]];
      const [e2, idn] = res[3 * i + 1] as [Error | null, (string | null)[]];
      const [e3, card] = res[3 * i + 2] as [Error | null, (string | null)[]];
      if (e1 || e2 || e3) throw e1 ?? e2 ?? e3;
      const [json, lastHash, expiresAt, profiles] = d;
      const current = activeLastHash(idn);
      if (json === null || current === null || lastHash !== current || !(Number(expiresAt) > now)) return null;
      // Listed only by a record published under the current KEL (CardStore).
      return { json, profiles: (profiles ?? '').split(' ').filter(Boolean), listed: card[0] === '1' && card[1] === current };
    });
  }
}
