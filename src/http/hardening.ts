import type { FastifyInstance } from 'fastify';
import { RelayError, relayBusy, sendError } from '../errors.js';

/**
 * Every rejection leaves as `{error: <07-relay code>, message?}`. Handlers throw RelayError; an oversized body is
 * `payload_too_large`; schema and body-parser failures are `invalid_argument`; a write the store refuses because it is
 * out of memory is the capacity refusal (`rate_limited`); an unknown route is 404 `not_found`; anything else is a 500.
 */
export function applyHttpHardening(app: FastifyInstance): void {
  app.setNotFoundHandler((_req, reply) => reply.status(404).send({ error: 'not_found' }));
  app.setErrorHandler((error, req, reply) => {
    if (error instanceof RelayError) return sendError(reply, error);
    const e = error as { validation?: unknown; code?: string; statusCode?: number; message?: string };
    if (e.code === 'FST_ERR_CTP_BODY_TOO_LARGE') return sendError(reply, new RelayError('payload_too_large'));
    // Redis' reply to a growing write while the store is at maxmemory (the high-water mark should have refused it first).
    if (error instanceof Error && error.name === 'ReplyError' && error.message.startsWith('OOM ')) {
      req.log.warn('the store is out of memory: a write was refused');
      return sendError(reply, relayBusy());
    }
    if (e.validation || (typeof e.code === 'string' && e.code.startsWith('FST_ERR_CTP_'))
      || (e.statusCode !== undefined && e.statusCode >= 400 && e.statusCode < 500)) {
      return sendError(reply, new RelayError('invalid_argument', e.message ?? 'malformed request'));
    }
    req.log.error({ err: error }, 'request_failed');
    return reply.status(500).send({ error: 'internal_error' });
  });
}
