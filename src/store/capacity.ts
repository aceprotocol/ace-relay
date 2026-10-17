import type Redis from 'ioredis';
import { MAY_GROW } from './lua.js';

/**
 * INFO memory as a script flagged as possibly writing: Redis refuses it whole while it refuses writes (out of memory,
 * failed persistence, read-only replica), which is exactly when growing writes would fail.
 */
const PROBE_SCRIPT = MAY_GROW + `return redis.call('INFO', 'memory')`;

export type StorageHealth = 'ok' | 'storage_high_water' | 'storage_refusing_writes';

type ScriptRedis = Redis & { storageProbe(): Promise<string> };

const usedOf = (info: string): number => Number(/^used_memory:(\d+)/m.exec(info)?.[1] ?? NaN);

/** The relay-wide capacity budget as operators see it: the store's used memory against STORAGE_HIGH_WATER_BYTES. */
export class StorageMonitor {
  private readonly redis: ScriptRedis;

  constructor(redis: Redis, private readonly highWaterBytes: number) {
    this.redis = redis as ScriptRedis;
    this.redis.defineCommand('storageProbe', { numberOfKeys: 0, lua: PROBE_SCRIPT });
  }

  /** The store's used memory (every relay key plus the server's overhead), the value the high-water mark compares. */
  async usedBytes(): Promise<number> {
    return usedOf(await this.redis.info('memory'));
  }

  /** `storage_refusing_writes` when the store refuses writes, `storage_high_water` when growth is refused. */
  async health(): Promise<StorageHealth> {
    let info: string;
    try {
      info = await this.redis.storageProbe();
    } catch (e) {
      if (e instanceof Error && e.name === 'ReplyError') return 'storage_refusing_writes';
      throw e;
    }
    return usedOf(info) >= this.highWaterBytes ? 'storage_high_water' : 'ok';
  }
}
