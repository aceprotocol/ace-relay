import type { FastifyReply } from 'fastify';
import { MAX_PACKET_BYTES } from '@ace-protocol/sdk';
import type Redis from 'ioredis';
import type { RelayConfig } from '../config.js';
import type { MessageStore, StreamEntry } from '../store/messages.js';
import { NOTIFY_KEY_PREFIX } from '../store/keyspace.js';
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
  killTimer?: NodeJS.Timeout;
}

/**
 * Most output one listen stream may have buffered in user space: one frame of the largest packet plus slack. A frame
 * that would exceed it closes the stream as a slow consumer.
 */
export const SSE_MAX_BUFFERED_BYTES = MAX_PACKET_BYTES + 64 * 1024;
/** After a graceful end, a stream whose socket has not closed within this many ms is destroyed. */
const END_GRACE_MS = 5000;

/**
 * Listen streams, bounded per identity and globally — never per IP address, because a hosted service serves many
 * identities from one address (07 § Listen). The inbox stream is the only delivery source. Pub/sub carries no payload: a
 * notification just wakes each connection's pump, which reads the stream from
 * that connection's cursor. Order and gap-freedom come from the stream, so a
 * lost or reordered notification is repaired by the next one, and those lost while the subscriber was disconnected by
 * the re-read every stream does when it is back (resume). Unregister publishes UNREGISTERED_NOTICE instead, which
 * evicts on every replica; the pump also refuses to write under a registration that is no longer current, which
 * covers a lost notice and re-registration.
 */
export class SseRegistry {
  private connections = new Map<string, Connection[]>(); // aceId → connections
  private totalCount = 0;
  private subscriptions = new Map<string, Promise<unknown>>();
  private subscriber: Redis;

  constructor(
    private redis: Redis,
    subscriberRedis: Redis, // separate connection for SUBSCRIBE
    private messageStore: Pick<MessageStore, 'getMessages'>,
    private identityStore: Pick<IdentityStore, 'currentRequestDigest'>,
    private config: RelayConfig,
    private log: StoreLogger = consoleLogger,
  ) {
    this.subscriber = subscriberRedis;
  }

  canConnect(aceId: string): { ok: boolean; error?: string } {
    if (this.totalCount >= this.config.globalSseLimit) return { ok: false, error: 'global_limit' };
    if ((this.connections.get(aceId)?.length ?? 0) >= this.config.ssePerIdentity) return { ok: false, error: 'identity_limit' };
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

    // Only subscribe when first connection for this aceId
    if (isFirst) {
      const subscription = this.subscriber.subscribe(NOTIFY_KEY_PREFIX + aceId);
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
    conns.splice(idx, 1);
    if (conns.length === 0) {
      this.connections.delete(aceId);
      this.subscriptions.delete(aceId);
      this.subscriber.unsubscribe(NOTIFY_KEY_PREFIX + aceId).catch((err: unknown) => {
        this.log.error({ err, aceId }, 'SSE unsubscribe failed');
      });
    }
    this.totalCount--;
  }

  /** Wakes the identity's streams on every replica; resolves with the number of replicas listening for it. */
  async notify(toAceId: string): Promise<number> {
    return this.redis.publish(NOTIFY_KEY_PREFIX + toAceId, '');
  }

  /** Whether any replica holds a listen stream of the identity (each subscribes its channel while it does). */
  async listening(aceId: string): Promise<boolean> {
    const [, n] = await this.redis.pubsub('NUMSUB', NOTIFY_KEY_PREFIX + aceId) as [string, number];
    return Number(n) > 0;
  }

  /** Closes the identity's streams here and, through the notify channel, on every other replica. */
  async unregistered(aceId: string): Promise<void> {
    this.evict(aceId);
    await this.redis.publish(NOTIFY_KEY_PREFIX + aceId, UNREGISTERED_NOTICE);
  }

  startListening(): void {
    this.subscriber.on('message', (channel: string, message: string) => {
      const aceId = channel.slice(NOTIFY_KEY_PREFIX.length);
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
    const channels = [...this.connections.keys()].map((aceId) => NOTIFY_KEY_PREFIX + aceId);
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
        let page;
        do {
          if (conn.closing || conn.reply.raw.destroyed || conn.reply.raw.writableEnded) return;
          page = await this.messageStore.getMessages(conn.aceId, conn.cursor, this.config.sseCatchupLimit);
          if (page.messages.length > 0 && (await this.identityStore.currentRequestDigest(conn.aceId)) !== conn.requestDigest) {
            this.close(conn, 'identity_unregistered');
            return;
          }
          for (const entry of page.messages) {
            if (!this.write(conn, sseFrame(conn.event, entry))) return;
            conn.cursor = entry.streamId;
            if (conn.reply.raw.writableNeedDrain && !(await this.drained(conn))) return;
          }
        } while (page.messages.length > 0);
      } while (conn.dirty);
    } catch (err) {
      this.log.error({ err, aceId: conn.aceId }, 'SSE inbox read failed');
      this.close(conn, 'read_error');
    } finally {
      conn.pumping = false;
    }
  }

  evict(aceId: string): void {
    const conns = this.connections.get(aceId);
    if (!conns) return;
    for (const conn of [...conns]) {
      this.close(conn, 'identity_unregistered');
    }
  }

  drain(): void {
    for (const [, conns] of this.connections) {
      for (const conn of conns) {
        try {
          conn.closing = true;
          clearInterval(conn.heartbeat);
          conn.reply.raw.write(`event: drain\ndata: {"reason":"server_shutdown"}\n\n`);
          conn.reply.raw.end();
        } catch {
          // Connection may already be closed
        }
      }
    }
    this.connections.clear();
    this.subscriptions.clear();
    this.totalCount = 0;
  }

  getStats(): { connections: number; identities: number } {
    return { connections: this.totalCount, identities: this.connections.size };
  }

  hasConnections(aceId: string): boolean {
    const conns = this.connections.get(aceId);
    return conns !== undefined && conns.length > 0;
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

  /** Writes unless the stream is closing or the frame would push its buffered output past SSE_MAX_BUFFERED_BYTES. */
  private write(conn: Connection, payload: string): boolean {
    const raw = conn.reply.raw;
    if (conn.closing) return false;
    if (raw.destroyed || raw.writableEnded) {
      this.close(conn, 'socket_closed');
      return false;
    }
    if (raw.writableLength + Buffer.byteLength(payload) > SSE_MAX_BUFFERED_BYTES) {
      this.close(conn, 'slow_consumer');
      return false;
    }
    try {
      raw.write(payload);
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
