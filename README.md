# ACE Relay

Store-and-forward relay for the ACE protocol. It registers identities (their KEL), serves their signed
descriptors and card records, binds handles, and queues opaque prekey-encrypted packets for registered recipients. It
never sees plaintext, never verifies packet signatures and is untrusted by design: clients verify every KEL,
descriptor, card record and packet themselves.
The public deployment is `https://relay.aceprotocol.org`.

The HTTP binding is normative in [`ace-spec/07-relay.md`](../ace-spec/07-relay.md) (its OpenAPI rendering,
`openapi.yaml`, lives only in ace-spec). Every protocol rule comes from `@ace-protocol/sdk` (`verifyRegistrationRequest`,
`verifyPublishedAgent`, `verifyCardBundle`, `verifyPermit`, `decodePacket`, `checkPacketTime`, `parseAuthHeaders` / `verifyAuthHeaders`,
`verifyKel` / `extendKel`, `networkKey` and the limit constants). `tests/e2e.test.ts` runs the SDK `NetworkClient`
between identities through one relay and across two; `tests/vectors.test.ts` replays ace-spec's `auth.negative` and
`auth.registration.negative` vectors through the HTTP routes.

Stack: Node 24, Fastify 5, Redis ≥ 6.2 / Valkey (streams, Lua), single node: scripts receive the keys named by the
request and derive the keys named by stored state (`src/store/keyspace.ts`).

## API

| Endpoint | Auth | Request | 2xx response |
|---|---|---|---|
| `POST /v1/register` | body signature | RegistrationRequest | `{ok, status: registered\|idempotent\|refreshed\|rotated}` |
| `POST /v1/unregister` | `unregister` | — | `{ok}` |
| `POST /v1/descriptor` | descriptor signature | PublishedAgent | `{ok}` |
| `GET /v1/descriptor/{aceId}` | — | — | PublishedAgent |
| `POST /v1/card` | card record signature | CardBundle | `{ok}` |
| `GET /v1/card/{aceId}` | — | — | CardBundle |
| `GET /v1/handles/{handle}` | — | — | CardBundle |
| `GET /v1/descriptors?profile&cursor&limit` | — | — | `{agents, cursor}` (listed identities) |
| `POST /v1/blocks` | `block` | `{peer, blocked, revision}` | `{ok}` |
| `POST /v1/send` | permit or `contact: open` recipient | `{packet, permit?}` | `{ok}` |
| `PUT /v1/wake` | `wake` | `{gateway, token}` | `{ok}` (only with `WAKE_GATEWAYS`) |
| `DELETE /v1/wake` | `wake` | — | `{ok}` (only with `WAKE_GATEWAYS`) |
| `GET /v1/inbox?since&limit` | `inbox` | — | `{messages: [{streamId, packet}], cursor}` |
| `POST /v1/inbox/ack?through` | `inbox-ack` | — | `{ok}` |
| `GET /v1/listen?since` | `listen` | — | `text/event-stream` |
| `GET /health` | — | — | `200 {ok: true}`; `503 {ok: false, error}` when Redis is unreachable (`redis_unavailable`), refuses writes (`storage_refusing_writes`: out of memory, failed persistence, read-only) or is at the high-water mark (`storage_high_water`) |

Any other route is `404 {"error":"not_found"}`. `GET /metrics` (Prometheus text: `ace_relay_sse_connections` and
`ace_relay_storage_used_bytes`) is served on the separate `METRICS_PORT`.

**Authentication.** `X-ACE-Id`, `X-ACE-Timestamp`, `X-ACE-Seq`, `X-ACE-Audience`, `X-ACE-Nonce`, `X-ACE-Signature`. The relay checks headers (`invalid_argument`), registration (`not_registered`), seq
(`stale_seq` / `future_seq`), audience, freshness, the registered KEL usable now and signed-while-live
(`stale_peer_binding`) and signature, then consumes the nonce
(`replay`, remembered `2 · TIMESTAMP_WINDOW_SECONDS + 1` = 601 s). A failed check consumes no nonce. The audience is
`PUBLIC_RELAY_URL`; it is never derived from `Host`, forwarded headers or the socket.

**Descriptors.** `POST /v1/descriptor` verifies the PublishedAgent, requires its KEL to be the registered KEL
(`not_registered`, `kel_conflict`), its `relays` to include this relay's public URL, and a newer `issuedAt`
(`stale_descriptor`; equal with identical claims is idempotent). The stored document's bytes are charged to the
identity's registration network (below; `429 rate_limited`). `GET /v1/descriptor/{aceId}` serves the unexpired
descriptor of any registered identity. Lookups return only complete signed documents of active identities, never
merged metadata.

**Card records and handles.** `POST /v1/card` verifies the CardBundle (`verifyCardBundle`), requires its KEL to be the
registered KEL (`not_registered`, `kel_conflict`) and a newer `issuedAt` (`stale_descriptor`; equal with identical
claims is idempotent), counts against `REGISTER_RATE_LIMIT` in a bucket of its own, and charges the stored bytes like
a descriptor. Handles are **set once, per home**, in the same script as the record (`src/store/cards.ts`):

- a record whose `home` is another relay is stored but claims nothing here; a handle already bound here stays bound;
- when `home` is this relay and a handle is bound to the identity here, the record must carry exactly that handle
  (omitting it or naming another is `400 invalid_argument`);
- otherwise a record at home naming a handle binds it permanently (`409 handle_taken` if another identity holds it).
  New bindings are limited to `HANDLE_CLAIMS_PER_NETWORK_PER_DAY` (8) per client network (`429 rate_limited`, with
  `Retry-After`).

A binding (`ace:handle:<h>` → ACE ID, `ace:handleof:<id>` → handle) has no TTL and is never released: not by a new
record, not by moving `home`, not by unregister. `GET /v1/handles/{handle}` serves the bound identity's stored
CardBundle only while that record names this relay as `home` and carries the handle, else `unknown_peer`.
`GET /v1/card/{aceId}` serves the stored record of a registered identity. A record is bound to the KEL it was
published under: after any KEL change (`dlg`, `rot`, recovery) it is treated as absent (not served, not listed,
`closed` for send) until the identity republishes a re-signed record; the handle binding is unaffected. **Agents must
republish their card record after every KEL change** (the SDK's upkeep does this). The directory lists identities whose stored record names this
relay as `home` and is `listed: true`, with an unexpired descriptor: ordered by ACE ID, at most 100 agents and 8 MiB
per page, scanning at most 1000 entries; continue until `cursor: null`.

**Permanent names and squatting.** Because a handle is never reassigned, a name claimed by an identity that is later
abandoned stays unusable for everyone. That is the price of handles nobody can take over. The relay bounds it with
`HANDLE_CLAIMS_PER_NETWORK_PER_DAY` per client network, plus the registration rate and byte budgets every claim also
passes. The spec also lets a relay reserve handles under a naming policy (answered `handle_taken`). This relay does not
implement such a policy yet; it is the place for a future operator hook (reserved or offensive names, trademark
disputes).

**Blocks.** Signed `{peer, blocked, revision}` with a strictly increasing revision per peer (`stale_revision`), kept
after an unblock; at most 1024 tracked peers per identity (`limit_exceeded`). A block wins over any permit at
`/v1/send`.

**Send.** In order: decode the packet (`invalid_packet`, `unsupported_version`) and require
`now − OFFLINE_WINDOW_SECONDS ≤ timestamp ≤ now + TIMESTAMP_WINDOW_SECONDS` (`stale_timestamp`); a byte-identical
packet already queued for a registered recipient is `{ok:true}` without enqueuing. A recipient that blocks `from` is
refused next, before any rate bucket or allowance slot is charged. With a permit (registered `to`,
issuer = `to`, subject = `from`, verified against `to`'s registered KEL, which must be usable now, valid) the packet
enters the **normal queue**:
retained `MESSAGE_TTL_SECONDS` (default `OFFLINE_WINDOW_SECONDS`), bounded per recipient by `MAX_INBOX_ENTRIES` and
`MAX_INBOX_BYTES`, with at most `MAX_INBOX_SENDER_BYTES` per (recipient, sender) (`recipient_inbox_full`), and
rate-limited per (recipient, sender). Without a permit the recipient must be
registered here with a stored card record that is `contact: open` and an unexpired descriptor: the packet enters the **stranger allowance**, at most
`STRANGER_ALLOWANCE` (16) entries per recipient, each retained `CONTACT_REQUEST_TTL_SECONDS` (86,400 s), of which one
client network holds at most `STRANGER_NETWORK_ALLOWANCE` (2) (`recipient_inbox_full`, with `Retry-After`), and
rate-limited per client network and per recipient. Unknown, unregistered, `closed` or card-less and blocking recipients and bad permits all answer
the same `403 {"error":"not_permitted","message":"not permitted"}`, so `/v1/send` cannot enumerate who takes contact
requests or block lists. The relay-wide capacity limit (below) answers `429 rate_limited` with `Retry-After`. Both kinds share the recipient's stream; listeners are then notified. Retries of one
message are re-encrypted and therefore distinct packets; receivers deduplicate by `(from, messageId)`.

**Inbox.** Reads never delete. `POST /v1/inbox/ack?through=<streamId>` deletes entries up to and including it
(idempotent). A page holds at most `limit` entries and 8 MiB, and at least one entry when any exists.

**Listen.** `event: connected`, then `catchup` entries after `since`, then live `message` entries, each
`data: {"packet": …}`; `: keepalive` heartbeats; `event: drain` on shutdown. Streams are bounded per identity
(`SSE_PER_IDENTITY`) and globally (`GLOBAL_SSE_LIMIT`), never per IP address, because a hosted service serves many
identities from one address. Unregister closes the identity's streams on every instance (an `unregistered` notice on
the notify channel); a stream also closes before writing a packet once the registration it was opened under is no
longer current, which covers a lost notice and re-registration.

**Wake hints** (optional, 07 § Wake hints). Off unless `WAKE_GATEWAYS` lists gateways (both routes are then
`404 not_found`). `PUT /v1/wake {gateway, token}` stores one registration per identity, armed, charged 3 KiB to the
identity's registration network once; `DELETE` removes it and its charge. After a send's response is written, an entry
queued for an identity whose registration is armed and that has no open listen stream on any instance (Valkey `PUBSUB
NUMSUB` of its notify channel) disarms it and sends one `POST <gateway>` with body `{"token": <token>}` (public DNS
answers only, pinned connection, no redirects, `WAKE_TIMEOUT_MS`, one retry after a transport failure, 5xx or 429).
Authenticated inbox, ack and listen requests re-arm it and restart its `OFFLINE_WINDOW_SECONDS` expiry; a wake due
within `WAKE_MIN_INTERVAL_SECONDS` of the previous one is deferred, not dropped. A gateway answering 404 or 410 loses
the registration. Unregister deletes it in the same script. The gateway contract: accept
`POST` with `Content-Type: application/json` and `{"token"}`, answer 2xx, or 404/410 for a token it no longer knows;
authenticate the relay, if at all, by arrangement (mTLS, source addresses).

**Registration.** `{aceId, kel, timestamp, audience, signature}` verified by `verifyRegistrationRequest`. The KEL's
bytes are charged to the registering network's byte budget (`429 rate_limited` when over it). New → `registered`;
same timestamp and digest → `idempotent`; newer timestamp, same last event → `refreshed`; extended or recovered KEL →
`rotated`; strict prefix → `stale_seq`; fork → `kel_conflict`; older timestamp, equal timestamp with another digest,
or at or below the unregister barrier → `identity_conflict`. `unregister` needs an auth timestamp newer than the
registration; it deletes queue, descriptor and card record documents, directory entry, blocks and wake registration atomically and closes listen
streams; the handle binding stays. The KEL, the descriptor's and card record's newest `issuedAt`/digest and the barrier are kept for `OFFLINE_WINDOW_SECONDS`
(their keys expire then), so a re-registration within that period must extend that history (or recover it, 01 rule
6). A fixed-size **horizon** stays forever (`ace:horizon:<id>`): the barrier, the descriptor's and card record's `issuedAt`/digest, the
seq and hash of the KEL's last root-epoch event (its last `icp` or `rot`) and of its last event. After the KEL expired,
a registration must carry that epoch event (`kel_conflict`) and either carry the last event (an extension) or hold a
`rot` after the epoch start, which only the holder of the committed next root can sign (recovery); otherwise it is
`stale_seq` when shorter than the retired log and `kel_conflict` when not, and its timestamp must exceed the barrier.
Superseded keys therefore cannot roll the identity back here.

**Errors** are `{error, message?}` with the codes and statuses of 07 § Errors; `rate_limited` and
`recipient_inbox_full` carry `Retry-After`; an oversized body is `payload_too_large` (413); an unknown route is 404
`not_found`.

## Configuration

| Env | Default | Meaning |
|---|---|---|
| `PUBLIC_RELAY_URL` | **required** (e.g. `http://localhost:3000` in development) | canonical public base URL: the auth audience, the route descriptors must list, and the handle authority; startup fails if missing, not canonical, or not `https` (loopback `http` is allowed only when `NODE_ENV` is not `production`) |
| `PORT` / `METRICS_PORT` | 3000 / 9090 | listen ports |
| `REDIS_URL` | `redis://localhost:6379` (development only) | Redis/Valkey; with `NODE_ENV=production` startup fails unless `REDIS_URL` or `REDIS_URL_FILE` is set |
| `REDIS_URL_FILE` | unset | file holding the Redis URL (preferred in deploy); must be 0400/0600; not together with `REDIS_URL` |
| `TRUST_PROXY` | unset (false) | proxy IP/CIDR list whose `X-Forwarded-For` is trusted; hop counts are rejected, and so is `true` (trust every peer) with `NODE_ENV=production` |
| `IP_RATE_LIMIT` | 600/min | per fine client network (IPv4 address, IPv6 /64), every `/v1` route |
| `REGISTER_RATE_LIMIT` | 20/h | registrations, and separately descriptor and card publications, per registration network (the client network, unless trusted) |
| `TRUSTED_REGISTER_RATE_LIMIT` | 2000/h | the same three limits for each `TRUSTED_REGISTRATION_NETWORKS` CIDR (one bucket per CIDR, shared by every identity a hosted service registers from it) |
| `DISCOVER_RATE_LIMIT` | 30/min | directory reads per fine client network |
| `SEND_RATE_LIMIT` | 120/min | permitted sends per (recipient, sender) |
| `STRANGER_IP_RATE_LIMIT` | 30/h | permit-less sends per client network |
| `STRANGER_RECIPIENT_RATE_LIMIT` | 60/h | permit-less sends per recipient |
| `HANDLE_CLAIMS_PER_NETWORK_PER_DAY` | 8/day | new handle bindings per client network (IPv4 /24, IPv6 /56), trusted networks included; 02 sets 8 |
| `MESSAGE_TTL_SECONDS` | 604800 | normal queue retention; must be 86400..604800 (`OFFLINE_WINDOW_SECONDS`) |
| `MAX_INBOX_ENTRIES` | 10000 | normal queue bound per recipient, entries |
| `MAX_INBOX_BYTES` | 24 MiB | normal queue bound per recipient, packet bytes (≥ `MAX_PACKET_BYTES`) |
| `MAX_INBOX_SENDER_BYTES` | 8 MiB | normal queue share per (recipient, sender), packet bytes (≥ `MAX_PACKET_BYTES`) |
| `REGISTRATION_NETWORK_BYTES` | 96 MiB | byte budget of one client network: the stored KELs, descriptors and card records of the identities registered from it, the KELs of identities retired from it (for the packet window), and the packets queued for them; a registration, publication or send over it gets `429 rate_limited` |
| `TRUSTED_REGISTRATION_NETWORKS` | unset | comma-separated CIDRs of operator-known registration egress; each listed CIDR is one network with the larger budget below and `TRUSTED_REGISTER_RATE_LIMIT`. For the hosted MCP this is the **docker bridge subnet it reaches the relay from** (`docker network inspect relay-network --format '{{(index .IPAM.Config 0).Subnet}}'`). Attribution: a registration the MCP triggers from a tool call carries the end user's forwarded IP (`X-Forwarded-For` through the proxy) and is charged to that user's client network; one its background worker triggers (descriptor renewal, re-registration) comes from the bridge subnet and is charged to the trusted network. **The hosted MCP deployment must set it**, or all its worker-triggered registrations share one client network's 96 MiB and 20/h |
| `TRUSTED_REGISTRATION_NETWORK_BYTES` | 256 MiB | budget of each trusted registration network |
| `STORAGE_HIGH_WATER_BYTES` | 384 MiB | relay-wide capacity: the store's **total** used memory (Valkey `used_memory`: identities, KELs, descriptors, horizons, queues, control keys and server overhead) at which registration, descriptor publication and send stop growing it (`429 rate_limited`, `Retry-After: 60`) and `/health` turns 503; set it below Valkey `maxmemory` with a reserve for control writes (default sized for 512 MiB) |
| `SSE_PER_IDENTITY` / `GLOBAL_SSE_LIMIT` | 3 / 10000 | listen stream bounds (`rate_limited`) |
| `HEARTBEAT_INTERVAL_MS` / `SSE_CATCHUP_LIMIT` / `DRAIN_MS` | 25000 / 200 / 10000 | listen heartbeat, read page, shutdown drain |
| `SSE_WRITE_TIMEOUT_MS` | 30000 | a listen stream whose output does not drain in time is destroyed |
| `WAKE_GATEWAYS` | unset | comma-separated canonical gateway URLs a wake registration may name (exact match); `*` alone accepts any public https gateway; unset offers no wake hints. A loopback `http://` gateway is accepted outside production only |
| `WAKE_MIN_INTERVAL_SECONDS` / `WAKE_TIMEOUT_MS` | 30 / 5000 | least interval between two wakes of one identity (later ones are deferred); bound of one wake request |

Integer variables must be plain non-negative integers; a malformed value fails startup. Protocol limits are fixed:
request bodies 64 KiB, except register and descriptor (`MAX_PUBLISHED_AGENT_BYTES`) and send
(`MAX_SEND_BODY_BYTES`); stranger allowance `STRANGER_ALLOWANCE` entries, `STRANGER_NETWORK_ALLOWANCE` per client
network, `CONTACT_REQUEST_TTL_SECONDS` each; inbox and directory pages 100 entries and 8 MiB. A **client network** is
an IPv4 /24 or an IPv6 /56 (`networkKey`), since one actor commonly holds a whole IPv6 allocation; the per-route limit
and directory reads use the fine network (IPv4 address, IPv6 /64).

## Resource bounds

- **Per recipient:** normal entries ≤ `MAX_INBOX_ENTRIES` and ≤ `MAX_INBOX_BYTES`, plus at most 16 stranger packets
  (≤ 32 MiB). Expired entries are dropped on the next enqueue or read, each exactly once, with their counters and
  dedup slot; queue keys expire after `MESSAGE_TTL_SECONDS` without traffic.
- **Senders are not authenticated.** A permitted packet is bound to a permit the recipient signed for `from`; a
  permit-less packet only ever lands in the stranger allowance of a public recipient, rate-limited per client network
  and per recipient, with at most `STRANGER_NETWORK_ALLOWANCE` entries per client network. A flood from many networks can fill a public recipient's stranger allowance (never its normal
  queue) for up to a day.
- **Storage is charged to the recipient that authorized it, and to the network it registered from.** A permitted packet is admitted only on a permit the
  recipient signed, so it lands in that recipient's queue bounds (`MAX_INBOX_BYTES`, `MAX_INBOX_ENTRIES`) and in the
  sender's share of them (`MAX_INBOX_SENDER_BYTES`). Nothing relay-wide is keyed on `from` (unauthenticated: anyone
  holding a self-issued permit can claim any `from`) or on the sending network (a hosted service or carrier NAT sends
  for many identities from one address). Each recipient's queued bytes are also charged to the network the relay saw
  it **register** from (its client network, or a `TRUSTED_REGISTRATION_NETWORKS` CIDR), which the relay observes
  directly: at most `REGISTRATION_NETWORK_BYTES` per network however many identities it registers. A re-registration
  from another network moves the queue's attribution on its next send; acks, expiry and unregister release it. Reaching
  the 384 MiB capacity limit therefore takes at least four registering networks (384 / 96), each also limited by
  `REGISTER_RATE_LIMIT`.
- **Identities and descriptors are charged to the same budget.** The stored KEL and descriptor bytes of every active
  identity count against its registration network (moved with it on re-registration), so one network cannot fill the
  store with registrations either. Unregister releases the descriptor at once; the retired KEL stays charged for the
  packet window (`MESSAGE_TTL_SECONDS`) and its keys expire after `OFFLINE_WINDOW_SECONDS`. Only the anti-rollback
  horizon is kept forever: fixed size, charged once for good as 512 bytes to the network the identity first retired
  from, so a network's permanent residue is bounded by its own budget (`REGISTRATION_NETWORK_BYTES` / 512 retired
  identities) as well as by `REGISTER_RATE_LIMIT`.
- **Relay-wide capacity.** One budget covers all relay data: the registration, descriptor and enqueue scripts read
  the store's `used_memory` (`INFO memory`) atomically and refuse a write that grows it once it is at
  `STORAGE_HIGH_WATER_BYTES` (07 § Send: `rate_limited` as a last resort before the store is exhausted). Growing
  scripts carry a plain `#!lua` shebang, so Redis refuses them whole rather than half-run once the store reaches
  `maxmemory` (`noeviction`). Only writes that free memory or rewrite in place — inbox purge, ack, unregister,
  unblocking an existing block record — carry `#!lua flags=allow-oom` and always run. The new small keys a draining
  request needs (the auth nonce of an inbox read, ack, unregister or unblock, and the per-client-network rate
  counters) are written past `maxmemory` only within a fixed 1 MiB reserve (`FULL_STORE_RESERVE_BYTES`), then refused
  too. Rate counters keyed on identities stop at the mark like other growth. A new block record is charged 256 bytes to
  the owner's registration network and refused at the mark. A write Redis refuses for memory is answered
  `429 rate_limited`, never 500. `/health` is
  503 at the mark or while Redis refuses writes. `/metrics` exports `ace_relay_storage_used_bytes`; alert well before
  the mark. The measure is instance-wide: anything else stored in the same Valkey counts against it.
- **Listen backpressure.** A stream writes a frame only while its buffered output stays under
  `MAX_PACKET_BYTES + 64 KiB`, waits for `drain` between frames, and is destroyed after `SSE_WRITE_TIMEOUT_MS` without
  draining. Its slot is released on the socket's `close`, not when it is closed, so stuck sockets stay counted.
- **Registration cost:** `POST /v1/register` verifies the whole KEL before reading the store; it is bounded by the
  registration and network rate limits. Concurrent registrations of one identity are re-checked until the store
  accepts or rejects them (at most 16 passes, then 500).
- Size Valkey `maxmemory` above `STORAGE_HIGH_WATER_BYTES` by a reserve for control writes (nonces and rate counters
  of the request rate over their windows) and one in-flight write per connection (at most `MAX_PACKET_BYTES` each);
  use `noeviction` (eviction would silently drop identities and queues). The default 384 MiB mark leaves 128 MiB of a
  512 MiB `maxmemory`.
- **Persistence is required.** Handle bindings and card records are permanent data (no TTL): a handle bound once must
  stay bound to its identity forever, and losing the store would let anyone claim it again. Run Valkey with
  `appendonly yes` and `appendfsync everysec` (the bundled `docker-compose.yml` enables AOF; everysec is Valkey's
  default fsync policy) on a persistent volume, and back the AOF up. An RDB-only or memory-only store is not enough.
- **One Valkey per service.** The relay and the MCP service must use separate Valkey instances with separate
  credentials (the deployment's `relay-valkey` serves only the relay). Under `noeviction` a shared instance lets one
  service's writes exhaust the other's memory, and a shared credential lets either read or flush the other's data.

## Deployment and TLS

TLS terminates in the host's nginx (`nginx.conf`), not in the container: the image serves
plain HTTP, and nginx proxies to it on `127.0.0.1`. Every `listen 443` server block sets

```nginx
ssl_protocols TLSv1.3;
ssl_ecdh_curve X25519MLKEM768:X25519;
```

TLS 1.3 only, with the hybrid post-quantum group `X25519MLKEM768` preferred and classical
`X25519` as the fallback. nginx must be linked against OpenSSL 3.5 or newer for
`X25519MLKEM768` to exist; check with `nginx -V` ("built with OpenSSL 3.5…" or later)
before reloading. The TLS protocol version and the supported groups (`ssl_ecdh_curve`) are
negotiated before SNI selects a vhost, so both come from the default server on the same
`:443` listener: it must also be TLS 1.3 only and carry the same `ssl_ecdh_curve`, or every
vhost on that listener silently loses `X25519MLKEM768`. The checks below detect either
violation; run them once per vhost name (`-servername`). To check a deployment:

```bash
echo | openssl s_client -connect relay.aceprotocol.org:443 -servername relay.aceprotocol.org \
  -tls1_3 -groups X25519MLKEM768 2>&1 | grep -E 'Negotiated TLS1.3 group|Protocol'
# expect: Negotiated TLS1.3 group: X25519MLKEM768 / Protocol: TLSv1.3
echo | openssl s_client -connect relay.aceprotocol.org:443 -tls1_2 2>&1 | grep -i alert
# expect a protocol version alert: TLS 1.2 is refused
```

(The client needs OpenSSL 3.5+ as well.) What was verified when this configuration was
written: with OpenSSL 3.6.5, a loopback `openssl s_server -tls1_3 -groups
X25519MLKEM768:X25519` negotiated `X25519MLKEM768` with an `-groups X25519MLKEM768` client,
fell back to `X25519` for an `X25519`-only client, and refused a TLS 1.2 client with
`alert protocol version`. `nginx -t` was not run (nginx is not installed on the machine
that made the change), and no deployed host was checked; run `nginx -t` and the
`s_client` check above on each host after deploying.

## Deploy

`.github/workflows/relay.yml` tests on every push to `test` and `main`, then builds, pushes and deploys in one job of
the GitHub environment `test` (from `test`) or `prod` (from `main`); give `prod` required reviewers. The job's OIDC
subject is therefore `repo:<org>/<repo>:environment:test` or `…:environment:prod`, so the trust policy of the
`AWS_ROLE_ARN` role must match those (not a branch ref). Every
deployment-specific value is an environment variable or secret (listed at the top of the workflow); the job fails
before building when one is missing, including `TRUSTED_REGISTRATION_NETWORKS` (the Docker network subnet the hosted
MCP reaches the relay from) and `STORAGE_HIGH_WATER_BYTES` (e.g. 402653184 under a 512 MiB `maxmemory`).
`TRUST_PROXY` is set at deploy to loopback, the Docker network's gateway (the host nginx's hop) and, when
`MCP_CONTAINER_IP` is set, the hosted MCP container's static address (ace-mcp pins it with `--ip`), since the MCP
forwards its users' addresses.
`nginx.conf` is a per-environment template (`RELAY_HOST`, `APP_PORT`; see its header).

**One-time flush.** A release that changes the stored format must start from an empty database: run the workflow by
hand (`workflow_dispatch`) with `flush_once: true`. After the old container stops and before the new one starts, it
runs `FLUSHDB` on that environment's relay db only (the password passes as `REDISCLI_AUTH` in the environment). Every
agent must register and publish again afterwards (SDK clients do so on their next `publish`/`maintain`). Push-triggered
runs never flush.

## Development

```bash
redis-server --port 16379 --save '' --daemonize yes   # tests use redis://localhost:16379/<1..15>; ../ace-spec holds the vectors
redis-server --port 16380 --save '' --daemonize yes   # the capacity suite owns this one (changes maxmemory)
npm ci && npm run lint && npm run typecheck && npm test && npm run build
```

Unreleased: storage and wire formats change without migration; use a fresh Redis database.
