import type Redis from 'ioredis';
import { MAX_PAGE_BYTES, isACEId, type CardBundle } from '@ace-protocol/sdk';
import {
  ACTIVE_FIELDS, CARD_KEY_PREFIX, DESCRIPTOR_KEY_PREFIX, DIRECTORY_KEY, DIRECTORY_TAG_KEY_PREFIX, HANDLE_KEY_PREFIX, HANDLE_OF_KEY_PREFIX,
  IDENTITY_KEY_PREFIX, RATE_KEY_PREFIX, activeLastHash, handleKey, handleSkeletonKey,
} from './keyspace.js';
import { BYTES_LUA, CAPACITY_LUA, DOCUMENT_LUA, IDENTITY_LUA, MAY_GROW, budgetArgs, type ByteBudget } from './lua.js';
import { parseStored } from '../errors.js';

/**
 * `handle_mismatch`: the record names this relay as home but not the handle bound to the identity here (or none).
 * `claim_limited`: binding a new handle would exceed the client network's daily claims.
 */
export type CardPublishStatus = 'published' | 'not_registered' | 'kel_conflict' | 'stale_descriptor' | 'handle_taken' | 'handle_mismatch'
  | 'claim_limited' | 'rate_limited' | 'relay_busy';

/** Window of the per-network handle claim counter (HANDLE_CLAIMS_PER_NETWORK_PER_DAY). */
const CLAIM_WINDOW_SECONDS = 86_400;
/** Directory entries one page may examine. */
const DIRECTORY_SCAN_BUDGET = 1000;
const DIRECTORY_BATCH = 200;
/** What a directory page holds besides its entries: `{"cards":[],"cursor":"<ACE ID>"}` (an ACE ID is 75 bytes). */
const PAGE_ENVELOPE_BYTES = 128;

/**
 * 07 § Descriptors and cards, in one script so the record, the handle binding and the directory entries change together.
 * KEYS: card hash, directory zset, identity hash, handle key (the record's handle, or the placeholder), handleof key,
 * claim counter, skeleton key (of the record's handle, or the placeholder). ARGV: aceId, issuedAt, claims digest, json,
 * registered lastHash, at home ('1' | '0'), handle ('' when none), contact, listed ('1' | '0'), claim limit, claim
 * window, the ByteBudget, binds handles ('1' | '0'), then the record's tags (space separated). Returns {status, retryAfter}.
 *
 * Handles are set once per home: once `handleof` holds a handle, every record naming this relay as home must carry it;
 * a record naming another home claims and changes nothing here. A relay that binds no handles (its public URL has a
 * path) neither checks nor writes a binding: a record naming it as home carries no handle (04 § Card record). A new
 * binding (handle, handleof and the handle's skeleton, no TTL) is counted against the client network's daily claims; a
 * handle whose skeleton another identity's bound handle holds is `handle_taken` (07: treated as reserved).
 * A listed record at home is a directory entry, and one entry of `directory-tag:<tag>` per tag; the record's `tags` field
 * keeps the tags indexed, so the next record, or unregister, removes exactly those. The json's bytes and the index
 * entries' (per tag: the ACE ID and the tag) are charged to the identity's registration network.
 * The record keeps the registered KEL's lastHash it was published under: after any KEL change (dlg, rot) it is treated
 * as absent (not served, `closed`, unlisted, and its `issuedAt` bounds no new record) until the identity republishes a
 * re-signed record; handle bindings stay.
 */
const PUBLISH_CARD_SCRIPT = MAY_GROW + IDENTITY_LUA + BYTES_LUA + CAPACITY_LUA + DOCUMENT_LUA + `
if not isActive(KEYS[3]) then return {'not_registered', 0} end
if redis.call('HGET', KEYS[3], 'lastHash') ~= ARGV[5] then return {'kel_conflict', 0} end
if isStale(KEYS[1], ARGV[5], ARGV[2], ARGV[3]) then return {'stale_descriptor', 0} end
local atHome, handle = ARGV[6] == '1', ARGV[7]
local bind, bound = false, nil
if atHome and ARGV[17] == '1' then
  bound = redis.call('GET', KEYS[5])
  if bound then
    if bound ~= handle then return {'handle_mismatch', 0} end
  elseif handle ~= '' then
    local owner = redis.call('GET', KEYS[4])
    if owner and owner ~= ARGV[1] then return {'handle_taken', 0} end
    local similar = redis.call('GET', KEYS[7])
    if similar and similar ~= ARGV[1] then return {'handle_taken', 0} end
    bind = true
  end
end
-- Only a handle bound to no identity is a new claim (a missing handleof beside our own binding is just restored).
local claim = bind and redis.call('EXISTS', KEYS[4]) == 0
if claim and tonumber(redis.call('GET', KEYS[6]) or '0') >= tonumber(ARGV[10]) then
  local ttl = redis.call('TTL', KEYS[6])
  if ttl < 1 then ttl = tonumber(ARGV[11]) end
  return {'claim_limited', ttl}
end
local listed = ARGV[9] == '1' and atHome
local tags, size = '', #ARGV[4]
if listed then
  tags = ARGV[18]
  for tag in string.gmatch(tags, '%S+') do size = size + #ARGV[1] + #tag end
end
local refused = chargeDocument(KEYS[1], KEYS[3], size, 12)
if refused then return {refused, 0} end
if bind then
  redis.call('SET', KEYS[4], ARGV[1])
  redis.call('SET', KEYS[5], handle)
  redis.call('SET', KEYS[7], ARGV[1])
end
if claim and redis.call('INCR', KEYS[6]) == 1 then redis.call('EXPIRE', KEYS[6], ARGV[11]) end
for tag in string.gmatch(redis.call('HGET', KEYS[1], 'tags') or '', '%S+') do
  redis.call('ZREM', '${DIRECTORY_TAG_KEY_PREFIX}' .. tag, ARGV[1])
end
for tag in string.gmatch(tags, '%S+') do redis.call('ZADD', '${DIRECTORY_TAG_KEY_PREFIX}' .. tag, 0, ARGV[1]) end
redis.call('HSET', KEYS[1], 'issuedAt', ARGV[2], 'digest', ARGV[3], 'json', ARGV[4], 'lastHash', ARGV[5], 'contact', ARGV[8],
  'listed', ARGV[9], 'tags', tags, 'jb', size)
if listed then redis.call('ZADD', KEYS[2], 0, ARGV[1]) else redis.call('ZREM', KEYS[2], ARGV[1]) end
return {'published', 0}
`;

type ScriptRedis = Redis & { publishCard(...keysAndArgs: (string | number)[]): Promise<[CardPublishStatus, number]> };

export interface CardWrite {
  bundle: CardBundle;
  /** The registered KEL's last hash the bundle's `kel` was checked against. */
  lastHash: string;
  /** documentDigest of the record. */
  digest: string;
  /** The client network the request came from (claim counting). */
  network: string;
}

/** Signed card records, the permanent handle bindings and the directory (07 § Descriptors and cards). */
export class CardStore {
  private readonly redis: ScriptRedis;
  /** Handles are written @name@host and resolve at https://host, so a relay whose public URL has a path binds none (04 § Card record). */
  private readonly bindsHandles: boolean;

  /** `home`: this relay's public URL, the home a record names. */
  constructor(redis: Redis, private readonly budget: ByteBudget, private readonly claimsPerDay: number, private readonly home: string) {
    this.redis = redis as ScriptRedis;
    this.bindsHandles = new URL(home).pathname === '/';
    this.redis.defineCommand('publishCard', { numberOfKeys: 7, lua: PUBLISH_CARD_SCRIPT });
  }

  async publish(w: CardWrite): Promise<{ status: CardPublishStatus; retryAfter: number }> {
    const r = w.bundle.card;
    // A relay that binds no handles neither checks nor writes a binding (a binding in a shared db is another relay's).
    const handle = this.bindsHandles ? r.handle ?? '' : '';
    const [status, retryAfter] = await this.redis.publishCard(
      CARD_KEY_PREFIX + r.aceId, DIRECTORY_KEY, IDENTITY_KEY_PREFIX + r.aceId, handleKey(handle), HANDLE_OF_KEY_PREFIX + r.aceId,
      `${RATE_KEY_PREFIX}handle-claim:${w.network}`, handleSkeletonKey(handle),
      r.aceId, r.issuedAt, w.digest, JSON.stringify(w.bundle), w.lastHash, r.home === this.home ? '1' : '0', handle, r.contact, r.listed ? '1' : '0',
      this.claimsPerDay, CLAIM_WINDOW_SECONDS, ...budgetArgs(this.budget), this.bindsHandles ? '1' : '0', (r.card.tags ?? []).join(' '),
    );
    return { status, retryAfter: Number(retryAfter) };
  }

  /**
   * The stored CardBundle of an active identity, published under its current KEL, or null. A record signed under a
   * superseded KEL carries no authorization (contact, listed) until it is re-signed.
   */
  async get(aceId: string): Promise<CardBundle | null> {
    if (!isACEId(aceId)) return null;
    const res = await this.redis.pipeline()
      .hmget(CARD_KEY_PREFIX + aceId, 'json', 'lastHash')
      .hmget(IDENTITY_KEY_PREFIX + aceId, ...ACTIVE_FIELDS)
      .exec();
    const [[e1, card], [e2, idn]] = res as [[Error | null, (string | null)[]], [Error | null, (string | null)[]]];
    if (e1 || e2) throw e1 ?? e2;
    const [json, lastHash] = card;
    return json !== null && lastHash !== null && lastHash === activeLastHash(idn) ? parseStored<CardBundle>(json, `card record of ${aceId}`) : null;
  }

  /**
   * The `contact` of the record published under `lastHash`, the registered KEL of an identity the caller read as active
   * (see `get`); no record is `closed` (04 § Card record).
   */
  async contactOf(aceId: string, lastHash: string): Promise<'open' | 'closed'> {
    const [contact, stored] = await this.redis.hmget(CARD_KEY_PREFIX + aceId, 'contact', 'lastHash');
    return contact === 'open' && stored === lastHash ? 'open' : 'closed';
  }

  /**
   * The CardBundle of the identity `handle` is bound to, when its stored record names this relay as home and carries the
   * handle; otherwise null (a binding outlives its record and a move to another home), and always on a relay that binds
   * no handles.
   */
  async resolveHandle(handle: string): Promise<CardBundle | null> {
    if (!this.bindsHandles) return null;
    const owner = await this.redis.get(HANDLE_KEY_PREFIX + handle);
    const bundle = owner === null ? null : await this.get(owner);
    return bundle !== null && bundle.card.home === this.home && bundle.card.handle === handle ? bundle : null;
  }

  /**
   * The directory page after `cursor` (07 § Descriptors and cards): the stored CardBundles of active identities whose
   * record, published under the current KEL, is listed and names this relay as home and whose stored descriptor
   * carries that KEL and is unexpired, by ACE ID; with `tag`, only records listing it (read from its index), with
   * `profile`, only identities whose descriptor lists it. At most `limit` entries, DIRECTORY_SCAN_BUDGET examined and
   * MAX_PAGE_BYTES serialized; at least one entry when any remain.
   */
  async directory(o: { cursor?: string; limit: number; tag?: string; profile?: string; now: number }): Promise<{ cards: CardBundle[]; cursor: string | null }> {
    const index = o.tag === undefined ? DIRECTORY_KEY : DIRECTORY_TAG_KEY_PREFIX + o.tag;
    const cards: CardBundle[] = [];
    let bytes = PAGE_ENVELOPE_BYTES;
    let scanned = 0;
    let after = o.cursor;
    for (;;) {
      const ids = await this.redis.zrangebylex(index, after ? `(${after}` : '-', '+', 'LIMIT', 0, DIRECTORY_BATCH);
      const rows = await this.rows(ids, o.now);
      for (let i = 0; i < ids.length; i++) {
        const row = rows[i];
        if (row && (o.tag === undefined || row.tags.includes(o.tag)) && (o.profile === undefined || row.profiles.includes(o.profile))) {
          const bundle = parseStored<CardBundle>(row.json, `card record of ${ids[i]}`);
          // A shared db may hold entries of a relay at another URL (a path replica): only records naming this one count.
          if (bundle.card.home === this.home) {
            const size = Buffer.byteLength(row.json) + 1;
            if (cards.length > 0 && bytes + size > MAX_PAGE_BYTES) return { cards, cursor: after ?? null };
            cards.push(bundle);
            bytes += size;
          }
        }
        after = ids[i];
        scanned++;
        if (cards.length === o.limit || scanned === DIRECTORY_SCAN_BUDGET) {
          const more = i < ids.length - 1 || (await this.redis.zrangebylex(index, `(${after}`, '+', 'LIMIT', 0, 1)).length > 0;
          return { cards, cursor: more ? after : null };
        }
      }
      if (ids.length < DIRECTORY_BATCH) return { cards, cursor: null };
    }
  }

  /**
   * Directory rows of active identities whose listed record and unexpired descriptor both carry their registered KEL,
   * else null.
   */
  private async rows(ids: string[], now: number): Promise<Array<{ json: string; tags: string[]; profiles: string[] } | null>> {
    if (ids.length === 0) return [];
    const pipe = this.redis.pipeline();
    for (const id of ids) {
      pipe.hmget(CARD_KEY_PREFIX + id, 'json', 'lastHash', 'listed', 'tags');
      pipe.hmget(DESCRIPTOR_KEY_PREFIX + id, 'lastHash', 'expiresAt', 'profiles');
      pipe.hmget(IDENTITY_KEY_PREFIX + id, ...ACTIVE_FIELDS);
    }
    const res = (await pipe.exec()) ?? [];
    return ids.map((_, i) => {
      const [e1, card] = res[3 * i] as [Error | null, (string | null)[]];
      const [e2, d] = res[3 * i + 1] as [Error | null, (string | null)[]];
      const [e3, idn] = res[3 * i + 2] as [Error | null, (string | null)[]];
      if (e1 || e2 || e3) throw e1 ?? e2 ?? e3;
      const [json, lastHash, listed, tags] = card;
      const [dLastHash, expiresAt, profiles] = d;
      const current = activeLastHash(idn);
      if (json === null || current === null || lastHash !== current || listed !== '1' || dLastHash !== current || !(Number(expiresAt) > now)) return null;
      return { json, tags: (tags ?? '').split(' ').filter(Boolean), profiles: (profiles ?? '').split(' ').filter(Boolean) };
    });
  }
}
