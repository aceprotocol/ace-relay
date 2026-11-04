import type { FastifyReply } from 'fastify';
import type Redis from 'ioredis';
import { SSE_MAX_BUFFERED_BYTES, type RelayConfig } from '../config.js';
import type { MessageStore, StreamEntry } from '../store/messages.js';
import { notifyPrefix } from '../store/keyspace.js';
import { consoleLogger, type IdentityStore, type StoreLogger } from '../store/identity.js';

/** 07 § Listen frame: the stored packet JSON is a single line. */
function sseFrame(event: 'catchup' | 'message', entry: StreamEntry): string {
  return `id: ${entry.streamId}\nevent: ${event}\ndata: {"packet":${entry.json}}\n\n`;
}

/** Notify-channel payload that evicts the identity's streams on every replica; any other payload wakes the pumps. */
export const UNREGISTERED_NOTICE = 'unregistered';

interface Connection {
  aceId: string;
  requestDigest: string; // the registration this stream was opened under
  reply: FastifyReply;
  heartbeat: NodeJS.Timeout;
  cursor: string; // last stream id written to this connection
  event: 'catchup' | 'message'; // 'catchup' until the first pump drains the backlog
  pumping: boolean;
  dirty: boolean; // a notification arrived while pumping; read again
  closing: boolean; // close() ran: nothing more is written; the slot is held until the socket's 'close'
  counted: number; // writableLength at its last write: an upper bound on its buffered bytes
  killTimer?: NodeJS.Timeout;
}

/** After a graceful end, a stream whose socket has not closed within this many ms is destroyed. */
const END_GRACE_MS = 5000;

/**
 * Listen streams, bounded per identity and globally — never per IP address, because a hosted service serves many
 * identities from one address (07 § Listen). The inbox stream is the only delivery source. Pub/sub carries no payload: a
 * notification wakes each connection's pump, which reads the stream from that connection's cursor. Order and
 * gap-freedom come from the stream, so a lost or reordered notification is repaired by the next one, and those lost
 * while the subscriber was disconnected by the re-read every stream does when it is back (resume). Unregister publishes
 * UNREGISTERED_NOTICE instead, which evicts on every replica; the pump also refuses to write under a registration that
 * is not current, which covers a lost notice and re-registration. Buffered output is bounded per stream
 * (SSE_MAX_BUFFERED_BYTES) and across all streams (sseBufferBytes); a page read from the stream is never held across a
 * wait for the socket to drain.
 */
export class SseRegistry {
  private connections = new Map<string, Connection[]>(); // aceId → connections
  private totalCount = 0;
  private subscriptions = new Map<string, Promise<unknown>>();
  private subscriber: Redis;
  /** Streams that had output buffered after their last write: the only ones that can hold buffered bytes. */
  private buffering = new Set<Connection>();
  /** Sum of `counted` over `buffering`: buffers only shrink between writes, so it bounds the bytes buffered. */
  private bufferedBound = 0;
  private draining = false;
  private readonly channelPrefix: string;

  constructor(
    private redis: Redis,
    subscriberRedis: Redis, // separate connection for SUBSCRIBE
    private messageStore: Pick<MessageStore, 'getMessages'>,
    private identityStore: Pick<IdentityStore, 'currentRequestDigest'>,
    private config: RelayConfig,
    private log: StoreLogger = consoleLogger,
  ) {
    this.subscriber = subscriberRedis;
    const db = redis.options.db ?? 0;
    if ((subscriberRedis.options.db ?? 0) !== db) throw new Error(`SseRegistry: subscriber db ${subscriberRedis.options.db} is not the store's db ${db}`);
    this.channelPrefix = notifyPrefix(db);
  }

  /** Whether `aceId` may open a stream now; a refusal names its reason and when to retry (seconds). */
  canConnect(aceId: string): { ok: true } | { ok: false; error: string; retryAfter: number } {
    if (this.draining) return { ok: false, error: 'draining', retryAfter: 1 };
    if (this.totalCount >= this.config.globalSseLimit) return { ok: false, error: 'global_limit', retryAfter: 60 };
    if ((this.connections.get(aceId)?.length ?? 0) >= this.config.ssePerIdentity) return { ok: false, error: 'identity_limit', retryAfter: 60 };
    return { ok: true };
  }

  /**
   * Registers the connection and resolves once its backlog after `cursor` is written.
   * Never rejects: a failed subscribe or read closes the connection instead.
   */
  async add(aceId: string, requestDigest: string, reply: FastifyReply, cursor: string): Promise<void> {
    const conn: Connection = {
      aceId,
      requestDigest,
      reply,
      cursor,
      event: 'catchup',
      pumping: false,
      dirty: false,
      closing: false,
      counted: 0,
      heartbeat: setInterval(() => {
        // Pending output already proves liveness; a stuck one is handled by the pump's drain timeout.
        if (conn.reply.raw.writableLength === 0) this.write(conn, ': keepalive\n\n');
      }, this.config.heartbeatIntervalMs),
    };

    const onError = () => this.close(conn, 'socket_error');
    // The slot is released only here, once the socket is gone, so a closed-but-buffered stream still counts.
    const onClose = () => {
      clearTimeout(conn.killTimer);
      this.remove(conn.aceId, conn.reply);
    };
    reply.raw.once('error', onError);
    reply.raw.once('close', onClose);

    const isFirst = !this.connections.has(aceId) || this.connections.get(aceId)!.length === 0;
    if (!this.connections.has(aceId)) this.connections.set(aceId, []);
    this.connections.get(aceId)!.push(conn);
    this.totalCount++;

    if (isFirst) {
      const subscription = this.subscriber.subscribe(this.channelPrefix + aceId);
      this.subscriptions.set(aceId, subscription);
      // A failed subscribe must not stick: the next connection retries it.
      subscription.catch(() => {
        if (this.subscriptions.get(aceId) === subscription) this.subscriptions.delete(aceId);
      });
    }
    // Subscribed before the first read, so nothing appended after it goes unannounced.
    try {
      await this.subscriptions.get(aceId);
    } catch (err) {
      this.log.error({ err, aceId }, 'SSE subscribe failed');
      this.close(conn, 'subscribe_error');
      return;
    }
    await this.pump(conn);
    conn.event = 'message';
  }

  remove(aceId: string, reply: FastifyReply): void {
    const conns = this.connections.get(aceId);
    if (!conns) return;
    const idx = conns.findIndex((c) => c.reply === reply);
    if (idx === -1) return;
    clearInterval(conns[idx].heartbeat);
    this.uncount(conns[idx]);
    conns.splice(idx, 1);
    if (conns.length === 0) {
      this.connections.delete(aceId);
      this.subscriptions.delete(aceId);
      this.subscriber.unsubscribe(this.channelPrefix + aceId).catch((err: unknown) => {
        this.log.error({ err, aceId }, 'SSE unsubscribe failed');
      });
    }
    this.totalCount--;
  }

  /** Wakes the identity's streams on every replica; resolves with the number of replicas listening for it. */
  async notify(toAceId: string): Promise<number> {
    return this.redis.publish(this.channelPrefix + toAceId, '');
  }

  /** Whether any replica holds a listen stream of the identity (each subscribes its channel while it does). */
  async listening(aceId: string): Promise<boolean> {
    const [, n] = await this.redis.pubsub('NUMSUB', this.channelPrefix + aceId) as [string, number];
    return Number(n) > 0;
  }

  /** Closes the identity's streams here and, through the notify channel, on every other replica. */
  async unregistered(aceId: string): Promise<void> {
    this.evict(aceId);
    await this.redis.publish(this.channelPrefix + aceId, UNREGISTERED_NOTICE);
  }

  startListening(): void {
    this.subscriber.on('message', (channel: string, message: string) => {
      const aceId = channel.slice(this.channelPrefix.length);
      if (message === UNREGISTERED_NOTICE) {
        this.evict(aceId);
        return;
      }
      const conns = this.connections.get(aceId);
      if (!conns) return;
      for (const conn of conns) void this.pump(conn);
    });
    this.subscriber.on('ready', () => void this.resume());
  }

  /**
   * After the subscriber reconnects: notifications published while it was down are lost, so once every stream's
   * channel is subscribed again, every stream re-reads its queue. A failed subscribe waits for the next 'ready'.
   */
  private async resume(): Promise<void> {
    const channels = [...this.connections.keys()].map((aceId) => this.channelPrefix + aceId);
    if (channels.length === 0) return;
    try {
      await this.subscriber.subscribe(...channels);
    } catch (err) {
      this.log.error({ err }, 'SSE resubscribe failed');
      return;
    }
    for (const conns of this.connections.values()) for (const conn of conns) void this.pump(conn);
  }

  /** Writes everything after conn.cursor. Serialized per connection; overlapping calls set `dirty`. */
  private async pump(conn: Connection): Promise<void> {
    if (conn.pumping) {
      conn.dirty = true;
      return;
    }
    conn.pumping = true;
    try {
      do {
        conn.dirty = false;
        for (;;) {
          const step = await this.writePage(conn);
          if (step === 'stop') return;
          if (step === 'empty') break;
          if (step === 'drain' && !(await this.drained(conn))) return;
        }
      } while (conn.dirty);
    } catch (err) {
      this.log.error({ err, aceId: conn.aceId }, 'SSE inbox read failed');
      this.close(conn, 'read_error');
    } finally {
      conn.pumping = false;
    }
  }

  /**
   * Reads one page after conn.cursor, at most what the socket takes before it needs draining (at least one entry), and
   * writes it. A page is never held while the pump waits for the socket, and never read twice.
   */
  private async writePage(conn: Connection): Promise<'empty' | 'more' | 'drain' | 'stop'> {
    const raw = conn.reply.raw;
    if (conn.closing || raw.destroyed || raw.writableEnded) return 'stop';
    const [page, digest] = await Promise.all([
      this.messageStore.getMessages(conn.aceId, conn.cursor, this.config.sseCatchupLimit, raw.writableHighWaterMark),
      this.identityStore.currentRequestDigest(conn.aceId),
    ]);
    if (page.messages.length === 0) return 'empty';
    if (digest !== conn.requestDigest) {
      this.close(conn, 'identity_unregistered');
      return 'stop';
    }
    for (const entry of page.messages) {
      if (!this.write(conn, sseFrame(conn.event, entry))) return 'stop';
      conn.cursor = entry.streamId;
      if (raw.writableNeedDrain) return 'drain';
    }
    return 'more';
  }

  evict(aceId: string): void {
    const conns = this.connections.get(aceId);
    if (!conns) return;
    for (const conn of [...conns]) {
      this.close(conn, 'identity_unregistered');
    }
  }

  /**
   * Shutdown: refuses new streams and ends every open one with `event: drain`; a socket that lingers is destroyed
   * after END_GRACE_MS, so the server's close never waits on a client.
   */
  drain(): void {
    this.draining = true;
    for (const conns of this.connections.values()) {
      for (const conn of [...conns]) {
        this.write(conn, 'event: drain\ndata: {"reason":"server_shutdown"}\n\n');
        this.close(conn, 'server_shutdown');
      }
    }
  }

  getStats(): { connections: number } {
    return { connections: this.totalCount };
  }

  /**
   * Resolves true once the socket drains, false (and the stream is destroyed) if it does not within
   * SSE_WRITE_TIMEOUT_MS or closes first.
   */
  private drained(conn: Connection): Promise<boolean> {
    const raw = conn.reply.raw;
    return new Promise((resolve) => {
      const done = (ok: boolean) => {
        clearTimeout(timer);
        raw.off('drain', onDrain);
        raw.off('close', onGone);
        if (!ok) this.close(conn, 'slow_consumer');
        resolve(ok);
      };
      const onDrain = () => done(true);
      const onGone = () => done(false);
      const timer = setTimeout(() => done(false), this.config.sseWriteTimeoutMs);
      raw.once('drain', onDrain);
      raw.once('close', onGone);
    });
  }

  /** Resets `bufferedBound` to the bytes buffered now, pruning streams that have drained. */
  private recount(): void {
    this.bufferedBound = 0;
    for (const c of this.buffering) {
      c.counted = c.reply.raw.writableLength;
      if (c.counted === 0) this.buffering.delete(c);
      else this.bufferedBound += c.counted;
    }
  }

  private uncount(conn: Connection): void {
    if (this.buffering.delete(conn)) this.bufferedBound -= conn.counted;
    conn.counted = 0;
  }

  /**
   * Writes unless the stream is closing or the frame would push its buffered output past SSE_MAX_BUFFERED_BYTES, or
   * all streams' past sseBufferBytes.
   */
  private write(conn: Connection, payload: string): boolean {
    const raw = conn.reply.raw;
    if (conn.closing) return false;
    if (raw.destroyed || raw.writableEnded) {
      this.close(conn, 'socket_closed');
      return false;
    }
    const size = Buffer.byteLength(payload);
    if (raw.writableLength + size > SSE_MAX_BUFFERED_BYTES) {
      this.close(conn, 'slow_consumer');
      return false;
    }
    if (this.bufferedBound + size > this.config.sseBufferBytes) this.recount();
    if (this.bufferedBound + size > this.config.sseBufferBytes) {
      this.log.error({ aceId: conn.aceId }, 'SSE buffer budget exhausted: stream closed');
      this.close(conn, 'buffer_budget');
      return false;
    }
    try {
      raw.write(payload);
      if (raw.writableLength > 0) {
        if (!this.buffering.has(conn)) { this.buffering.add(conn); conn.counted = 0; }
        this.bufferedBound += raw.writableLength - conn.counted;
        conn.counted = raw.writableLength;
      }
      return true;
    } catch {
      this.close(conn, 'write_error');
      return false;
    }
  }

  /**
   * Stops writing and tears the socket down; the slot stays counted until the socket's 'close' event. Nothing
   * buffered → a graceful end, destroyed after END_GRACE_MS if the socket lingers; buffered output (a slow or stuck
   * consumer) → destroyed at once, which frees its buffers.
   */
  private close(conn: Connection, reason: string): void {
    if (conn.closing) return;
    conn.closing = true;
    clearInterval(conn.heartbeat);
    const raw = conn.reply.raw;
    if (raw.closed) {
      this.remove(conn.aceId, conn.reply);
      return;
    }
    try {
      if (raw.writableLength === 0 && !raw.destroyed && reason !== 'slow_consumer') {
        raw.end();
        conn.killTimer = setTimeout(() => raw.destroy(), END_GRACE_MS);
        conn.killTimer.unref();
      } else {
        raw.destroy();
      }
    } catch {
      raw.destroy();
    }
  }
}
