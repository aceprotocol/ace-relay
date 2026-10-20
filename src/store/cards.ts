import type Redis from 'ioredis';
import { isACEId, type CardBundle } from '@ace-protocol/sdk';
import { CARD_KEY_PREFIX, DIRECTORY_KEY, HANDLE_KEY_PREFIX, HANDLE_OF_KEY_PREFIX, IDENTITY_KEY_PREFIX, RATE_KEY_PREFIX, handleKey } from './keyspace.js';
import { BYTES_LUA, CAPACITY_LUA, IDENTITY_LUA, MAY_GROW, budgetArgs, type ByteBudget } from './lua.js';
import { StorageError } from '../errors.js';

/**
 * `handle_mismatch`: the record names this relay as home but not the handle bound to the identity here (or none).
 * `claim_limited`: binding a new handle would exceed the client network's daily claims.
 */
export type CardPublishStatus = 'published' | 'not_registered' | 'kel_conflict' | 'stale_descriptor' | 'handle_taken' | 'handle_mismatch'
  | 'claim_limited' | 'rate_limited' | 'relay_busy';

/** Window of the per-network handle claim counter (HANDLE_CLAIMS_PER_NETWORK_PER_DAY). */
const CLAIM_WINDOW_SECONDS = 86_400;

/**
 * 07 § Descriptors and cards, in one script so the record, the handle binding and the directory entry change together.
 * KEYS: card hash, directory zset, identity hash, handle key (the record's handle, or the placeholder), handleof key,
 * claim counter. ARGV: aceId, issuedAt, claims digest, json, registered lastHash, at home ('1' | '0'), handle ('' when
 * none), contact, listed ('1' | '0'), claim limit, claim window, the ByteBudget, then binds handles ('1' | '0'). Returns
 * {status, retryAfter}.
 *
 * Handles are set once per home: once `handleof` holds a handle, every record naming this relay as home must carry it;
 * a record naming another home claims and changes nothing here. A relay that binds no handles (its public URL has a
 * path) neither checks nor writes a binding: a record naming it as home carries no handle (04 § Card record). A new binding (handle and handleof, no TTL) is counted
 * against the client network's daily claims. The json's bytes are charged to the identity's registration network.
 * The record keeps the registered KEL's lastHash it was published under: after any KEL change (dlg, rot) it is treated
 * as absent (not served, `closed`, unlisted) until the identity republishes a re-signed record; handle bindings stay.
 */
const PUBLISH_CARD_SCRIPT = MAY_GROW + IDENTITY_LUA + BYTES_LUA + CAPACITY_LUA + `
if not isActive(KEYS[3]) then return {'not_registered', 0} end
if redis.call('HGET', KEYS[3], 'lastHash') ~= ARGV[5] then return {'kel_conflict', 0} end
local at = tonumber(redis.call('HGET', KEYS[1], 'issuedAt') or '-1')
local issuedAt = tonumber(ARGV[2])
if at > issuedAt then return {'stale_descriptor', 0} end
if at == issuedAt and redis.call('HGET', KEYS[1], 'digest') ~= ARGV[3] then return {'stale_descriptor', 0} end
local atHome, handle = ARGV[6] == '1', ARGV[7]
local bind = false
if atHome and ARGV[17] == '1' then
  local bound = redis.call('GET', KEYS[5])
  if bound then
    if bound ~= handle then return {'handle_mismatch', 0} end
  elseif handle ~= '' then
    local owner = redis.call('GET', KEYS[4])
    if owner and owner ~= ARGV[1] then return {'handle_taken', 0} end
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
local rn = redis.call('HGET', KEYS[3], 'regnet')
local delta = #ARGV[4] - tonumber(redis.call('HGET', KEYS[1], 'jb') or '0')
if rn and overBudget(rn, delta, tonumber(ARGV[12]), tonumber(ARGV[13]), tonumber(ARGV[14]), tonumber(ARGV[15])) then return {'rate_limited', 0} end
if delta > 0 and atCapacity(tonumber(ARGV[16])) then return {'relay_busy', 0} end
charge(rn, delta)
if bind then
  redis.call('SET', KEYS[4], ARGV[1])
  redis.call('SET', KEYS[5], handle)
end
if claim and redis.call('INCR', KEYS[6]) == 1 then redis.call('EXPIRE', KEYS[6], ARGV[11]) end
redis.call('HSET', KEYS[1], 'issuedAt', ARGV[2], 'digest', ARGV[3], 'json', ARGV[4], 'lastHash', ARGV[5], 'contact', ARGV[8],
  'listed', ARGV[9], 'jb', #ARGV[4])
if ARGV[9] == '1' and atHome then redis.call('ZADD', KEYS[2], 0, ARGV[1]) else redis.call('ZREM', KEYS[2], ARGV[1]) end
return {'published', 0}
`;

type ScriptRedis = Redis & { publishCard(...keysAndArgs: (string | number)[]): Promise<[CardPublishStatus, number]> };

export interface CardWrite {
  bundle: CardBundle;
  /** The registered KEL's last hash the bundle's `kel` was checked against. */
  lastHash: string;
  /** documentDigest of the record. */
  digest: string;
  /** Whether the record's `home` is this relay. */
  atHome: boolean;
  /** Whether this relay binds handles (its public URL has no path); when not, a record's handle claims nothing here. */
  bindsHandles: boolean;
  /** The client network the request came from (claim counting). */
  network: string;
}

/** Signed card records and the permanent handle bindings (07 § Descriptors and cards). */
export class CardStore {
  private readonly redis: ScriptRedis;

  constructor(redis: Redis, private readonly budget: ByteBudget, private readonly claimsPerDay: number) {
    this.redis = redis as ScriptRedis;
    this.redis.defineCommand('publishCard', { numberOfKeys: 6, lua: PUBLISH_CARD_SCRIPT });
  }

  async publish(w: CardWrite): Promise<{ status: CardPublishStatus; retryAfter: number }> {
    const r = w.bundle.card;
    // A relay that binds no handles neither checks nor writes a binding (a binding in a shared db is another relay's).
    const handle = w.bindsHandles ? r.handle ?? '' : '';
    const [status, retryAfter] = await this.redis.publishCard(
      CARD_KEY_PREFIX + r.aceId, DIRECTORY_KEY, IDENTITY_KEY_PREFIX + r.aceId, handleKey(handle), HANDLE_OF_KEY_PREFIX + r.aceId,
      `${RATE_KEY_PREFIX}handle-claim:${w.network}`,
      r.aceId, r.issuedAt, w.digest, JSON.stringify(w.bundle), w.lastHash, w.atHome ? '1' : '0', handle, r.contact, r.listed ? '1' : '0',
      this.claimsPerDay, CLAIM_WINDOW_SECONDS, ...budgetArgs(this.budget), w.bindsHandles ? '1' : '0',
    );
    return { status, retryAfter: Number(retryAfter) };
  }

  /** The stored CardBundle of an active identity, published under its current KEL, or null. */
  async get(aceId: string): Promise<CardBundle | null> {
    if (!isACEId(aceId)) return null;
    const [json, active] = await this.fields(aceId, 'json');
    return json !== null && active !== null ? parse(aceId, json) : null;
  }

  /** The `contact` of the current record (see `get`); no record is `closed` (04 § Card record). */
  async contactOf(aceId: string): Promise<'open' | 'closed'> {
    const [contact, active] = await this.fields(aceId, 'contact');
    return active !== null && contact === 'open' ? 'open' : 'closed';
  }

  /**
   * The CardBundle of the identity `handle` is bound to, when its stored record names `home` and carries the handle;
   * otherwise null (a binding outlives its record and a move to another home).
   */
  async resolveHandle(handle: string, home: string): Promise<CardBundle | null> {
    const owner = await this.redis.get(HANDLE_KEY_PREFIX + handle);
    if (owner === null || !isACEId(owner)) return null;
    const bundle = await this.get(owner);
    return bundle !== null && bundle.card.home === home && bundle.card.handle === handle ? bundle : null;
  }

  /**
   * [card field, '1' when the identity is active and the record was published under its current KEL, else null]. A
   * record signed under a superseded KEL carries no authorization (contact, listed) until it is re-signed.
   */
  private async fields(aceId: string, field: 'json' | 'contact'): Promise<[string | null, string | null]> {
    const res = await this.redis.pipeline()
      .hmget(CARD_KEY_PREFIX + aceId, field, 'lastHash')
      .hmget(IDENTITY_KEY_PREFIX + aceId, 'signingPublicKey', 'retiredAt', 'lastHash')
      .exec();
    const [[e1, card], [e2, idn]] = res as [[Error | null, (string | null)[]], [Error | null, (string | null)[]]];
    if (e1 || e2) throw e1 ?? e2;
    const current = idn[0] !== null && idn[1] === null && card[1] !== null && card[1] === idn[2];
    return [card[0], current ? '1' : null];
  }
}

function parse(aceId: string, json: string): CardBundle {
  try {
    return JSON.parse(json) as CardBundle;
  } catch {
    throw new StorageError(`corrupt card record of ${aceId}`);
  }
}
