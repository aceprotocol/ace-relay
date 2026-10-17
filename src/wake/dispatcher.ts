import { publicHttpsFetch } from '@ace-protocol/sdk';
import { acceptsGateway, type RelayConfig } from '../config.js';
import type { WakeStore } from '../store/wake.js';
import { consoleLogger, type StoreLogger } from '../store/identity.js';

/** Bytes of a gateway response that are read (and discarded). */
const RESPONSE_LIMIT_BYTES = 4096;
/** Delay before the single retry of a wake that failed in transport or with 5xx / 429. */
const RETRY_DELAY_MS = 1000;

/**
 * Sends wakes (07 § Wake hints). The send route calls `queued` once its response is written, and only when no
 * listen stream of the recipient received the entry, so neither the response nor its timing depends on the
 * recipient's registration. An armed registration is disarmed and woken; one due within the minimum interval is
 * deferred, and checked for a listen stream again when it is due. Gateways the operator no longer accepts are never
 * contacted.
 */
export class WakeDispatcher {
  private readonly deferred = new Map<string, NodeJS.Timeout>();
  private readonly fetch: typeof fetch;
  private closed = false;

  constructor(
    private readonly store: WakeStore,
    private readonly sse: { listening(aceId: string): Promise<boolean> },
    private readonly config: RelayConfig,
    private readonly log: StoreLogger = consoleLogger,
    fetchImpl?: typeof fetch,
  ) {
    // Public DNS answers only, pinned connection, no redirects, bounded time and body (the client rules' policy).
    this.fetch = fetchImpl ?? publicHttpsFetch({ timeoutMs: config.wakeTimeoutMs, maxResponseBytes: RESPONSE_LIMIT_BYTES });
  }

  get enabled(): boolean {
    return this.config.wakeGateways.length > 0;
  }

  /** An entry was queued for `aceId` and no listen stream took it. Never throws; the work runs detached. */
  queued(aceId: string): void {
    if (this.closed || this.deferred.has(aceId)) return;
    void this.run(aceId).catch((err: unknown) => this.log.error({ err, aceId }, 'wake failed'));
  }

  close(): void {
    this.closed = true;
    for (const t of this.deferred.values()) clearTimeout(t);
    this.deferred.clear();
  }

  private async run(aceId: string): Promise<void> {
    const taken = await this.store.take(aceId, Date.now(), this.config.wakeMinIntervalSeconds * 1000);
    if (taken === null) return;
    if ('deferMs' in taken) {
      if (this.closed || this.deferred.has(aceId)) return;
      const timer = setTimeout(() => {
        this.deferred.delete(aceId);
        // The registration stays armed; a stream opened meanwhile delivers instead.
        void this.sse.listening(aceId).then((on) => { if (!on) this.queued(aceId); })
          .catch((err: unknown) => this.log.error({ err, aceId }, 'wake failed'));
      }, taken.deferMs);
      timer.unref();
      this.deferred.set(aceId, timer);
      return;
    }
    const { gateway, token } = taken.wake;
    if (!acceptsGateway(this.config, gateway)) return;
    for (let attempt = 0; attempt < 2; attempt++) {
      if (attempt > 0) await new Promise((r) => setTimeout(r, RETRY_DELAY_MS).unref());
      let status: number;
      try {
        status = (await this.fetch(gateway, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token }) })).status;
      } catch (err) {
        this.log.error({ err: err instanceof Error ? err.message : String(err), aceId, attempt }, 'wake request failed');
        continue;
      }
      if (status === 404 || status === 410) {
        await this.store.clear(aceId, token); // the gateway no longer knows the token
        return;
      }
      if (status < 500 && status !== 429) return; // 2xx, or a refusal a retry cannot change
    }
  }
}
