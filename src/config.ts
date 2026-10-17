import { readFileSync, statSync } from 'node:fs';
import { BlockList, isIP } from 'node:net';
import { CONTACT_REQUEST_TTL_SECONDS, MAX_PACKET_BYTES, OFFLINE_WINDOW_SECONDS, isCanonicalRelayUrl, normalizeRelayUrl } from '@ace-protocol/sdk';

/** Request body limit of the routes without their own (07 sets MAX_PUBLISHED_AGENT_BYTES and MAX_SEND_BODY_BYTES). */
export const BODY_LIMIT_BYTES = 64 * 1024;

/** An operator-trusted registration network: its CIDR (the attribution key) and a matcher for it. */
export interface TrustedNetwork {
  cidr: string;
  list: BlockList;
}

export interface RelayConfig {
  port: number;
  metricsPort: number;
  /** The canonical public URL: the authentication audience, the route descriptors list, the handle authority. */
  publicRelayUrl: string;
  redisUrl: string;
  /**
   * Reverse-proxy trust: how req.ip is derived for every IP rate limit. false (default) uses the socket peer; an
   * IP/CIDR list trusts those proxies. Hop counts are refused (Fastify fails closed on them).
   */
  trustProxy: boolean | string;

  /** Requests per minute per fine client network (IPv4 address, IPv6 /64), on every route. */
  ipRateLimit: number;
  /** Registrations, and separately descriptor publications, per hour per untrusted client network. */
  registerRateLimit: number;
  /** Registrations (and separately descriptor publications) per hour from one trusted registration network. */
  trustedRegisterRateLimit: number;
  /** Directory reads per minute per fine client network. */
  discoverRateLimit: number;
  /** Permitted sends per minute per (recipient, sender). */
  sendRateLimit: number;
  /** Stranger (permit-less) sends per hour per client network. */
  strangerIpRateLimit: number;
  /** Stranger sends per hour per recipient. */
  strangerRecipientRateLimit: number;

  /** Normal queue retention, at most OFFLINE_WINDOW_SECONDS. */
  messageTtlSeconds: number;
  /** Normal queue bound per recipient, entries. */
  maxInboxEntries: number;
  /** Normal queue bound per recipient, packet bytes. */
  maxInboxBytes: number;
  /**
   * Normal queue bound per (recipient, sender), packet bytes. Storage is charged to the recipient that issued the
   * permit; `from` is unauthenticated, so this share only ever limits one recipient's queue.
   */
  maxInboxSenderBytes: number;
  /**
   * Relay-wide capacity: the store's total used memory (all relay data plus server overhead) at which registration,
   * descriptor publication and send are refused with 429 and /health turns 503. Set it below the store's maxmemory,
   * leaving a reserve for control writes (nonces, rate counters) and freeing paths.
   */
  storageHighWaterBytes: number;
  /**
   * Byte budget of one client network (07 § Registration, § Send): the stored KEL and descriptor bytes of the
   * identities registered from it plus the packet bytes queued for them. Writes over it are refused.
   */
  registrationNetworkBytes: number;
  /** Operator-known registration egress (e.g. a hosted service): each listed network gets the larger budget. */
  trustedRegistrationNetworks: TrustedNetwork[];
  trustedRegistrationNetworkBytes: number;

  ssePerIdentity: number;
  globalSseLimit: number;
  heartbeatIntervalMs: number;
  drainMs: number;
  sseCatchupLimit: number;
  /** A listen stream whose buffered output does not drain within this many ms is destroyed. */
  sseWriteTimeoutMs: number;

  /**
   * Wake hints (07 § Wake hints): the gateways a registration may name, as canonical https URLs compared exactly; `*`
   * alone accepts any public https gateway. Empty (the default) offers no wake hints: both routes answer 404 not_found.
   */
  wakeGateways: string[];
  /** Least interval between two wakes of one identity; a wake due sooner is deferred, never dropped. */
  wakeMinIntervalSeconds: number;
  /** Bound of one wake request (DNS, connect and response). */
  wakeTimeoutMs: number;
}

/** WAKE_GATEWAYS value accepting any public https gateway. */
export const ANY_WAKE_GATEWAY = '*';

/** `address/prefix` CIDRs (IPv4 or IPv6), parsed once into matchers. A malformed entry throws. */
export function parseCidrs(list: readonly string[]): TrustedNetwork[] {
  return list.map((cidr) => {
    const m = /^([^/]+)\/(\d{1,3})$/.exec(cidr);
    const family = m ? isIP(m[1]) : 0;
    const prefix = m ? Number(m[2]) : -1;
    if (!m || family === 0 || prefix > (family === 4 ? 32 : 128)) throw new Error(`TRUSTED_REGISTRATION_NETWORKS: ${cidr} is not an address/prefix CIDR`);
    const matcher = new BlockList();
    matcher.addSubnet(m[1], prefix, family === 4 ? 'ipv4' : 'ipv6');
    return { cidr, list: matcher };
  });
}

/** A comma-separated list from the environment, entries trimmed, empty ones dropped. */
function envList(key: string): string[] {
  return (process.env[key] ?? '').split(',').map((x) => x.trim()).filter((x) => x !== '');
}

/** A non-negative integer from the environment. A malformed value fails startup. */
export function envInt(key: string, fallback: number): number {
  const v = process.env[key];
  const t = v?.trim();
  if (t === undefined || t === '') return fallback;
  const n = Number(t);
  if (!/^[0-9]+$/.test(t) || !Number.isSafeInteger(n)) throw new Error(`${key}=${v}: expected a non-negative integer`);
  return n;
}

/** Reads a secret file that is not group- or world-accessible; errors never include its content. */
function readSecretFile(key: string, file: string): string {
  let mode: number;
  let text: string;
  try {
    mode = statSync(file).mode;
    text = readFileSync(file, 'utf8');
  } catch (e) {
    throw new Error(`${key}=${file}: cannot read (${(e as NodeJS.ErrnoException).code ?? 'error'})`);
  }
  if (process.platform !== 'win32' && (mode & 0o077) !== 0) {
    throw new Error(`${key}=${file}: mode ${(mode & 0o777).toString(8).padStart(4, '0')} is group/world-accessible; chmod 0400 (or 0600) it`);
  }
  return text.trim();
}

/**
 * REDIS_URL_FILE (preferred: keeps the password out of the environment) or REDIS_URL, not both. Only development falls
 * back to a local Redis; production requires one of them.
 */
function envRedisUrl(production: boolean): string {
  const file = process.env.REDIS_URL_FILE?.trim();
  const inline = process.env.REDIS_URL?.trim();
  if (file && inline) throw new Error('set either REDIS_URL_FILE or REDIS_URL, not both');
  if (!file && !inline && production) throw new Error('REDIS_URL_FILE or REDIS_URL is required in production');
  if (!file) return inline || 'redis://localhost:6379';
  const url = readSecretFile('REDIS_URL_FILE', file);
  if (!/^rediss?:\/\/\S+$/.test(url)) throw new Error(`REDIS_URL_FILE=${file}: expected a redis:// or rediss:// URL`);
  return url;
}

/** TRUST_PROXY: unset → false; "true"/"false"; otherwise an IP/CIDR list. A hop count fails startup. */
export function envTrustProxy(): boolean | string {
  const t = process.env.TRUST_PROXY?.trim();
  if (!t) return false;
  if (t === 'true') return true;
  if (t === 'false') return false;
  if (/^\d+$/.test(t)) {
    throw new Error(`TRUST_PROXY=${t}: hop counts are not supported — set the proxy/gateway address(es) (e.g. "loopback,172.30.0.1": the Docker gateway the host proxy connects from)`);
  }
  return t;
}

/** PUBLIC_RELAY_URL in canonical form. A missing or non-canonical URL fails startup. */
function envPublicRelayUrl(): string {
  const v = process.env.PUBLIC_RELAY_URL?.trim();
  if (!v) throw new Error('PUBLIC_RELAY_URL is required: it is the authentication audience');
  const canonical = normalizeRelayUrl(v);
  if (canonical !== v) throw new Error(`PUBLIC_RELAY_URL=${v}: not canonical; use ${canonical}`);
  return canonical;
}

/** Rejects configurations the spec forbids or that cannot work. */
export function validateConfig(c: RelayConfig, production = process.env.NODE_ENV === 'production'): RelayConfig {
  // https, or loopback http for development only (02 § Relay URLs).
  if (!isCanonicalRelayUrl(c.publicRelayUrl, { allowLoopback: !production })) {
    throw new Error(`PUBLIC_RELAY_URL=${c.publicRelayUrl}: must be a canonical https URL${production ? '' : ' or a loopback http URL'}`);
  }
  // Trusting every peer's X-Forwarded-For lets any client choose the address every IP limit keys on.
  if (production && c.trustProxy === true) throw new Error('TRUST_PROXY=true trusts every peer in production; list the proxy addresses');
  if (c.messageTtlSeconds < CONTACT_REQUEST_TTL_SECONDS || c.messageTtlSeconds > OFFLINE_WINDOW_SECONDS) {
    throw new Error(`MESSAGE_TTL_SECONDS=${c.messageTtlSeconds}: must be in ${CONTACT_REQUEST_TTL_SECONDS}..${OFFLINE_WINDOW_SECONDS}`);
  }
  for (const [name, value] of [
    ['MAX_INBOX_BYTES', c.maxInboxBytes],
    ['MAX_INBOX_SENDER_BYTES', c.maxInboxSenderBytes],
    ['REGISTRATION_NETWORK_BYTES', c.registrationNetworkBytes],
    ['TRUSTED_REGISTRATION_NETWORK_BYTES', c.trustedRegistrationNetworkBytes],
    ['STORAGE_HIGH_WATER_BYTES', c.storageHighWaterBytes],
  ] as const) {
    if (value < MAX_PACKET_BYTES) throw new Error(`${name} must be at least MAX_PACKET_BYTES (${MAX_PACKET_BYTES})`);
  }
  for (const [name, value] of [
    ['MAX_INBOX_ENTRIES', c.maxInboxEntries],
    ['SSE_PER_IDENTITY', c.ssePerIdentity],
    ['SSE_CATCHUP_LIMIT', c.sseCatchupLimit],
    ['SSE_WRITE_TIMEOUT_MS', c.sseWriteTimeoutMs],
    ['HEARTBEAT_INTERVAL_MS', c.heartbeatIntervalMs],
    ['WAKE_TIMEOUT_MS', c.wakeTimeoutMs],
  ] as const) {
    if (value < 1) throw new Error(`${name}=${value}: must be at least 1`);
  }
  if (c.wakeGateways.includes(ANY_WAKE_GATEWAY) && c.wakeGateways.length !== 1) throw new Error(`WAKE_GATEWAYS: '${ANY_WAKE_GATEWAY}' must stand alone`);
  for (const g of c.wakeGateways) {
    if (g !== ANY_WAKE_GATEWAY && !isCanonicalRelayUrl(g, { allowLoopback: false })) throw new Error(`WAKE_GATEWAYS: ${g} must be a canonical https URL`);
  }
  return c;
}

/**
 * Whether a wake registration may name `gateway` (07 § Wake hints): a listed gateway (validated at startup), or with
 * `*` any canonical https URL. The wake request itself only reaches public addresses.
 */
export function acceptsGateway(c: RelayConfig, gateway: string): boolean {
  return c.wakeGateways[0] === ANY_WAKE_GATEWAY ? isCanonicalRelayUrl(gateway, { allowLoopback: false }) : c.wakeGateways.includes(gateway);
}

export function loadConfig(production = process.env.NODE_ENV === 'production'): RelayConfig {
  return validateConfig({
    port: envInt('PORT', 3000),
    metricsPort: envInt('METRICS_PORT', 9090),
    publicRelayUrl: envPublicRelayUrl(),
    redisUrl: envRedisUrl(production),
    trustProxy: envTrustProxy(),

    ipRateLimit: envInt('IP_RATE_LIMIT', 600),
    registerRateLimit: envInt('REGISTER_RATE_LIMIT', 20),
    trustedRegisterRateLimit: envInt('TRUSTED_REGISTER_RATE_LIMIT', 2000),
    discoverRateLimit: envInt('DISCOVER_RATE_LIMIT', 30),
    sendRateLimit: envInt('SEND_RATE_LIMIT', 120),
    strangerIpRateLimit: envInt('STRANGER_IP_RATE_LIMIT', 30),
    strangerRecipientRateLimit: envInt('STRANGER_RECIPIENT_RATE_LIMIT', 60),

    messageTtlSeconds: envInt('MESSAGE_TTL_SECONDS', OFFLINE_WINDOW_SECONDS),
    maxInboxEntries: envInt('MAX_INBOX_ENTRIES', 10_000),
    maxInboxBytes: envInt('MAX_INBOX_BYTES', 24 * 1024 * 1024),
    maxInboxSenderBytes: envInt('MAX_INBOX_SENDER_BYTES', 8 * 1024 * 1024),
    storageHighWaterBytes: envInt('STORAGE_HIGH_WATER_BYTES', 384 * 1024 * 1024),
    registrationNetworkBytes: envInt('REGISTRATION_NETWORK_BYTES', 96 * 1024 * 1024),
    trustedRegistrationNetworks: parseCidrs(envList('TRUSTED_REGISTRATION_NETWORKS')),
    trustedRegistrationNetworkBytes: envInt('TRUSTED_REGISTRATION_NETWORK_BYTES', 256 * 1024 * 1024),

    ssePerIdentity: envInt('SSE_PER_IDENTITY', 3),
    globalSseLimit: envInt('GLOBAL_SSE_LIMIT', 10_000),
    heartbeatIntervalMs: envInt('HEARTBEAT_INTERVAL_MS', 25_000),
    drainMs: envInt('DRAIN_MS', 10_000),
    sseCatchupLimit: envInt('SSE_CATCHUP_LIMIT', 200),
    sseWriteTimeoutMs: envInt('SSE_WRITE_TIMEOUT_MS', 30_000),

    wakeGateways: envList('WAKE_GATEWAYS'),
    wakeMinIntervalSeconds: envInt('WAKE_MIN_INTERVAL_SECONDS', 30),
    wakeTimeoutMs: envInt('WAKE_TIMEOUT_MS', 5_000),
  }, production);
}
