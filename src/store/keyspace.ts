/**
 * Redis keyspace. Every key is built here from a validated ACE ID, handle or digest. Lua scripts receive the keys they
 * name from the request as KEYS and derive keys named by stored state: `regnet:<rn>` from the recipient's registration
 * network, `handle:<h>` from the stored descriptor's handle. This needs single-node Valkey (under Cluster these
 * scripts already span slots and would need hash tags).
 *
 * | prefix            | type   | lifetime                                                                  |
 * |-------------------|--------|---------------------------------------------------------------------------|
 * | identity:<id>     | hash   | KEL, signing seq/key, registration timestamp, kb (charged KEL bytes),      |
 * |                   |        | bb (charged block bytes), regnet; after unregister a retiredAt barrier,    |
 * |                   |        | expiring OFFLINE_WINDOW                                                   |
 * | horizon:<id>      | hash   | forever, written at unregister (fixed size): retiredAt, epochSeq +        |
 * |                   |        | epochStartHash, lastSeq + lastHash, descriptor issuedAt + digest           |
 * | descriptor:<id>   | hash   | newest issuedAt + claims digest (as long as the identity); json/handle/jb  |
 * |                   |        | (charged json bytes) until unregister                                      |
 * | descriptors       | zset   | public directory (lex by ACE ID)                                          |
 * | handle:<handle>   | string | owner ACE ID, expires with the descriptor                                 |
 * | blocks:<id>       | hash   | peer → "<revision>:<0|1>", until unregister                               |
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
export const HANDLE_KEY_PREFIX = 'ace:handle:';
export const BLOCKS_KEY_PREFIX = 'ace:blocks:';
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

/** The four keys of one recipient queue, in the order the queue scripts take them. */
export function queueKeys(aceId: string): [string, string, string, string] {
  return [INBOX_KEY_PREFIX + aceId, INBOX_META_KEY_PREFIX + aceId, INBOX_DEDUP_KEY_PREFIX + aceId, INBOX_STRANGERS_KEY_PREFIX + aceId];
}
