import Redis from 'ioredis';

export function createRedisClient(url: string): Redis {
  return new Redis(url, {
    maxRetriesPerRequest: 3,
    retryStrategy(times) {
      return Math.min(times * 200, 3000);
    },
  });
}
