/**
 * Redis keyspace. Every key is built here from a validated ACE ID, handle or digest. Lua scripts receive the keys they
 * name from the request as KEYS and derive keys named by stored state or by a verified record's tags: `regnet:<rn>`
 * from the recipient's registration network, `directory-tag:<tag>` from a card record's `tags` (stored and new). This
 * needs single-node Valkey (under Cluster these scripts already span slots and would need hash tags).
 *
 * | prefix            | type   | lifetime                                                                  |
 * |-------------------|--------|---------------------------------------------------------------------------|
 * | identity:<id>     | hash   | KEL, signing seq/key, registration timestamp, kb (charged KEL bytes),      |
 * |                   |        | bb (charged block bytes), wb (charged wake bytes), regnet; after          |
 * |                   |        | unregister a retiredAt barrier,                                           |
 * |                   |        | expiring OFFLINE_WINDOW                                                   |
 * | horizon:<id>      | hash   | forever, written at unregister (fixed size): retiredAt, epochSeq +        |
 * |                   |        | epochStartHash, lastSeq + lastHash, descriptor issuedAt + digest, card    |
 * |                   |        | cardIssuedAt + cardDigest                                                 |
 * | descriptor:<id>   | hash   | newest issuedAt + claims digest (as long as the identity); json/lastHash/  |
 * |                   |        | expiresAt/profiles/jb (charged json bytes) until unregister; absent       |
 * |                   |        | (not served, no bar to publishing) while lastHash is not the registered   |
 * |                   |        | KEL's                                                                     |
 * | card:<id>         | hash   | newest issuedAt + claims digest (as long as the identity); json/lastHash/  |
 * |                   |        | contact/listed/tags (the tags indexed under directory-tag:)/jb (charged   |
 * |                   |        | json and tag index bytes) until unregister; no TTL while registered;      |
 * |                   |        | ignored while lastHash is not the registered KEL's                        |
 * | descriptors       | zset   | directory: identities whose card record is listed at home (lex by ACE ID) |
 * | directory-tag:<tag> | zset | the directory entries whose card lists <tag>; follows descriptors, its    |
 * |                   |        | bytes charged in the card's jb; empty sets vanish                         |
 * | handle:<handle>   | string | owner ACE ID; permanent, never reassigned (no TTL, survives unregister)   |
 * | handleof:<id>     | string | the identity's handle at this relay; permanent like handle:<handle>       |
 * | handle-skeleton:<s> | string | ACE ID of the bound handle with skeleton <s> (`handleSkeleton`);       |
 * |                   |        | permanent like handle:<handle>                                            |
 * | blocks:<id>       | hash   | peer → "<revision>:<0|1>", until unregister                               |
 * | wake:<id>         | hash   | g (gateway), t (token), a (armed 1|0), w (last wake ms); expires          |
 * |                   |        | OFFLINE_WINDOW after the identity's last wake/inbox/ack/listen; deleted   |
 * |                   |        | at unregister                                                             |
 * | inbox:<id>        | stream | packets; fields json, n, k (n|s), d (digest), b (bucket), f (from) | c (net) |
 * | inbox-meta:<id>   | hash   | nn/nb (normal), fb:<from> (normal bytes per sender), sn (stranger),       |
 * |                   |        | sc:<net> (stranger entries per network), g:<bucket> (bytes per bucket),   |
 * |                   |        | rn (registration network the queue's bytes are attributed to)             |
 * | inbox-dedup:<id>  | hash   | packet digest → stream ID of queued packets                               |
 * | inbox-strangers:<id> | zset | stranger stream IDs by expiry ms                                         |
 * | regnet:<n|t>:<net> | hash  | retained bytes by bucket of recipients registered from that network       |
 * |                   |        | (queued packets, and the KELs of identities retired from it)              |
 * | regnet-stored:<n|t>:<net> | string | stored KEL + descriptor bytes of its active identities         |
 * | replay:<id>:<nonce> | string | auth nonce guard, REPLAY_TTL_SECONDS                                    |
 * | rate:<bucket>     | string | fixed-window counters                                                     |
 * | notify:<id>       | pubsub | payload-free wake-ups for listen streams                                  |
 */
export const IDENTITY_KEY_PREFIX = 'ace:identity:';
export const HORIZON_KEY_PREFIX = 'ace:horizon:';
export const DESCRIPTOR_KEY_PREFIX = 'ace:descriptor:';
export const DIRECTORY_KEY = 'ace:descriptors';
export const CARD_KEY_PREFIX = 'ace:card:';
export const HANDLE_KEY_PREFIX = 'ace:handle:';
export const HANDLE_OF_KEY_PREFIX = 'ace:handleof:';
export const HANDLE_SKELETON_KEY_PREFIX = 'ace:handle-skeleton:';
export const DIRECTORY_TAG_KEY_PREFIX = 'ace:directory-tag:';
export const BLOCKS_KEY_PREFIX = 'ace:blocks:';
export const WAKE_KEY_PREFIX = 'ace:wake:';
export const INBOX_KEY_PREFIX = 'ace:inbox:';
export const INBOX_META_KEY_PREFIX = 'ace:inbox-meta:';
export const INBOX_DEDUP_KEY_PREFIX = 'ace:inbox-dedup:';
export const INBOX_STRANGERS_KEY_PREFIX = 'ace:inbox-strangers:';
export const REGNET_KEY_PREFIX = 'ace:regnet:';
export const REGNET_STORED_KEY_PREFIX = 'ace:regnet-stored:';
export const REPLAY_KEY_PREFIX = 'ace:replay:';
export const RATE_KEY_PREFIX = 'ace:rate:';
export const NOTIFY_KEY_PREFIX = 'ace:notify:';

/** The key of a claimed handle; '' (no handle) names a placeholder key a script may declare but never holds. */
export function handleKey(handle: string): string {
  return HANDLE_KEY_PREFIX + (handle || '-');
}

/**
 * A handle's skeleton (07 § Descriptors and cards): its hyphens removed, `0` read as `o` and `1` as `l`, so
 * `alice-bot`, `alicebot` and `a1icebot` share one.
 */
export function handleSkeleton(handle: string): string {
  return handle.replaceAll('-', '').replaceAll('0', 'o').replaceAll('1', 'l');
}

/** The skeleton key of a handle; '' names a placeholder like `handleKey` (no skeleton is '-'). */
export function handleSkeletonKey(handle: string): string {
  return HANDLE_SKELETON_KEY_PREFIX + (handle ? handleSkeleton(handle) : '-');
}

/** The four keys of one recipient queue, in the order the queue scripts take them. */
export function queueKeys(aceId: string): [string, string, string, string] {
  return [INBOX_KEY_PREFIX + aceId, INBOX_META_KEY_PREFIX + aceId, INBOX_DEDUP_KEY_PREFIX + aceId, INBOX_STRANGERS_KEY_PREFIX + aceId];
}

/** The identity hash fields `activeLastHash` takes, in order. */
export const ACTIVE_FIELDS = ['lastHash', 'signingPublicKey', 'retiredAt'] as const;

/**
 * The registered KEL's lastHash of an active identity (ACTIVE_FIELDS values), else null. A published document
 * (descriptor, card record) counts only while its stored lastHash is this one (07 § Descriptors and cards).
 */
export function activeLastHash([lastHash, signingPublicKey, retiredAt]: (string | null)[]): string | null {
  return signingPublicKey !== null && retiredAt === null ? lastHash : null;
}
