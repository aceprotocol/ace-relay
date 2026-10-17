import type { FastifyReply } from 'fastify';
import { ACEError } from '@ace-protocol/sdk';

/** Error codes and statuses of ace-spec 07-relay.md § Errors (`internal_error` is the error handler's). */
const RELAY_ERRORS = {
  invalid_argument: 400,
  invalid_packet: 400,
  unsupported_version: 400,
  invalid_registration: 400,
  invalid_kel: 400,
  stale_timestamp: 400,
  invalid_signature: 401,
  invalid_authorization: 401,
  stale_seq: 401,
  stale_peer_binding: 401,
  not_registered: 403,
  not_permitted: 403,
  unknown_peer: 404,
  replay: 409,
  identity_conflict: 409,
  future_seq: 409,
  kel_conflict: 409,
  stale_descriptor: 409,
  handle_taken: 409,
  stale_revision: 409,
  limit_exceeded: 409,
  payload_too_large: 413,
  rate_limited: 429,
  recipient_inbox_full: 429,
} as const;

export type RelayErrorCode = keyof typeof RELAY_ERRORS;

/** Retry-After of a write refused for storage (a network's byte budget, a full queue, the high-water mark). */
export const BUSY_RETRY_SECONDS = 60;

/** The relay-wide capacity refusal (07 § Send: `rate_limited` as a last resort before the store is exhausted). */
export const relayBusy = (): RelayError => new RelayError('rate_limited', 'relay storage is at capacity', BUSY_RETRY_SECONDS);

/** A rejection a handler or store raises; the error handler turns it into `{error, message?}`. */
export class RelayError extends Error {
  constructor(
    readonly code: RelayErrorCode,
    message?: string,
    readonly retryAfterSeconds?: number,
  ) {
    super(message ?? code);
    this.name = 'RelayError';
  }
}

/** A stored record the relay cannot read (corruption): answered 500 `internal_error` and logged. */
export class StorageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StorageError';
  }
}

export function sendError(reply: FastifyReply, err: RelayError): FastifyReply {
  if (err.retryAfterSeconds !== undefined) reply.header('Retry-After', String(err.retryAfterSeconds));
  const body: { error: RelayErrorCode; message?: string } = { error: err.code };
  if (err.message !== err.code) body.message = err.message;
  return reply.status(RELAY_ERRORS[err.code]).send(body);
}

/** Runs an SDK call; an ACEError becomes the relay error with the same code. Any other SDK code is a relay bug. */
export function sdk<T>(f: () => T): T {
  try {
    return f();
  } catch (e) {
    throw fromACEError(e);
  }
}

/** SDK codes that are relay codes pass through; anything else rethrows (a 500). */
export function fromACEError(e: unknown): RelayError {
  if (!(e instanceof ACEError)) throw e;
  const detail = e.message.startsWith(`${e.code}: `) ? e.message.slice(e.code.length + 2) : e.message;
  if (e.code in RELAY_ERRORS) return new RelayError(e.code as RelayErrorCode, detail);
  throw e;
}
