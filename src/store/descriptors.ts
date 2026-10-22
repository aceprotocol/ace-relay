import type Redis from 'ioredis';
import type { PublishedAgent } from '@ace-protocol/sdk';
import { ACTIVE_FIELDS, DESCRIPTOR_KEY_PREFIX, IDENTITY_KEY_PREFIX, activeLastHash } from './keyspace.js';
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
local refused = chargeDocument(KEYS[1], KEYS[2], #ARGV[4], 8)
if refused then return refused end
redis.call('HSET', KEYS[1], 'issuedAt', ARGV[2], 'digest', ARGV[3], 'json', ARGV[4], 'lastHash', ARGV[5],
  'expiresAt', ARGV[6], 'profiles', ARGV[7], 'jb', #ARGV[4])
return 'published'
`;

type ScriptRedis = Redis & { publishDescriptor(...keysAndArgs: (string | number)[]): Promise<PublishStatus> };

/** Signed PublishedAgents. Only complete signed documents are stored and served; the directory is CardStore's. */
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
    const res = await this.redis.pipeline()
      .hmget(DESCRIPTOR_KEY_PREFIX + aceId, 'json', 'lastHash', 'expiresAt')
      .hmget(IDENTITY_KEY_PREFIX + aceId, ...ACTIVE_FIELDS)
      .exec();
    const [[e1, d], [e2, idn]] = res as [[Error | null, (string | null)[]], [Error | null, (string | null)[]]];
    if (e1 || e2) throw e1 ?? e2;
    const [json, lastHash, expiresAt] = d;
    const current = activeLastHash(idn);
    return json !== null && current !== null && lastHash === current && Number(expiresAt) > now
      ? parseStored<PublishedAgent>(json, `descriptor of ${aceId}`) : null;
  }

  /**
   * Whether the stored descriptor carries `lastHash`, the registered KEL of an identity the caller read as active, and is
   * unexpired (see `get`), without reading the document.
   */
  async isLive(aceId: string, lastHash: string, now: number): Promise<boolean> {
    const [stored, expiresAt] = await this.redis.hmget(DESCRIPTOR_KEY_PREFIX + aceId, 'lastHash', 'expiresAt');
    return stored === lastHash && Number(expiresAt) > now;
  }
}
