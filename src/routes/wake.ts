import type { FastifyInstance, FastifyRequest } from 'fastify';
import { WAKE_TOKEN_RE } from '@ace-protocol/sdk';
import { acceptsGateway } from '../config.js';
import type { WakeStore } from '../store/wake.js';
import { RelayError, storageRefusal } from '../errors.js';
import { authenticate, type RouteDeps } from './shared.js';

const wakeSchema = {
  body: {
    type: 'object',
    additionalProperties: false,
    required: ['gateway', 'token'],
    properties: { gateway: { type: 'string', maxLength: 2048 }, token: { type: 'string', pattern: WAKE_TOKEN_RE.source } },
  },
} as const;

/** 07 § Wake hints. Registered only when the operator lists gateways; otherwise both routes are 404 not_found. */
export async function wakeRoutes(app: FastifyInstance, deps: RouteDeps & { wakes: WakeStore }): Promise<void> {
  const { wakes, config } = deps;

  app.put('/v1/wake', { schema: wakeSchema }, async (req: FastifyRequest) => {
    const { gateway, token } = req.body as { gateway: string; token: string };
    if (!acceptsGateway(config, gateway)) throw new RelayError('invalid_argument', 'gateway is not accepted by this relay');
    const { identity } = await authenticate(deps, req, { action: 'wake', gateway, token });
    const status = await wakes.set(identity.aceId, gateway, token, identity.lastHash);
    if (status === 'rate_limited' || status === 'relay_busy') throw storageRefusal(status);
    if (status !== 'ok') throw new RelayError(status);
    return { ok: true };
  });

  app.delete('/v1/wake', async (req: FastifyRequest) => {
    const { identity } = await authenticate(deps, req, { action: 'wake' });
    await wakes.clear(identity.aceId);
    return { ok: true };
  });
}
