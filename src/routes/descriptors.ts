import type { FastifyInstance, FastifyRequest } from 'fastify';
import {
  DEFAULT_PAGE_LIMIT, MAX_INBOX_PAGE, MAX_PUBLISHED_AGENT_BYTES, documentDigest, isACEId, isHandle, verifyPublishedAgent,
} from '@ace-protocol/sdk';
import type { DescriptorStore } from '../store/descriptors.js';
import type { BlockStore } from '../store/blocks.js';
import { RelayError, sdk, storageRefusal } from '../errors.js';
import { authenticate, clientOf, enforceRate, enforceRegistrationRate, permittedSubject, type RouteDeps } from './shared.js';

interface DescriptorDeps extends RouteDeps {
  descriptors: DescriptorStore;
  blocks: BlockStore;
}

const directorySchema = {
  querystring: {
    type: 'object',
    additionalProperties: false,
    properties: {
      profile: { type: 'string', maxLength: 256 },
      cursor: { type: 'string', maxLength: 512 },
      limit: { type: 'integer', minimum: 1, maximum: MAX_INBOX_PAGE },
    },
  },
} as const;

const resolveSchema = {
  body: {
    type: 'object',
    additionalProperties: false,
    required: ['aceId', 'permit'],
    properties: { aceId: { type: 'string' }, permit: {} },
  },
} as const;

const blockSchema = {
  body: {
    type: 'object',
    additionalProperties: false,
    required: ['peer', 'blocked', 'revision'],
    properties: { peer: { type: 'string' }, blocked: { type: 'boolean' }, revision: { type: 'integer', minimum: 0, maximum: Number.MAX_SAFE_INTEGER } },
  },
} as const;

/** 07 § Descriptors and § Blocks. */
export async function descriptorRoutes(app: FastifyInstance, deps: DescriptorDeps): Promise<void> {
  const { identityStore, descriptors, blocks, rateLimiter, config, clock } = deps;

  app.post('/v1/descriptor', { bodyLimit: MAX_PUBLISHED_AGENT_BYTES }, async (req: FastifyRequest) => {
    await enforceRegistrationRate(deps, req, 'descriptor');
    const now = clock();
    const audience = config.publicRelayUrl;
    const { agent, state } = sdk(() => verifyPublishedAgent(req.body, now, { allowLoopbackRelays: audience.startsWith('http://') }));
    const d = agent.descriptor;
    if (!d.relays.includes(audience)) throw new RelayError('invalid_argument', `descriptor relays must include ${audience}`);
    // A handle is claimed only where this relay is the primary route. The store checks the registration and its KEL.
    const handle = d.visibility === 'public' && d.handle !== undefined && d.relays[0] === audience ? d.handle : '';
    const status = await descriptors.publish(agent, state.lastHash, documentDigest(d), handle, now);
    if (status === 'rate_limited' || status === 'relay_busy') throw storageRefusal(status);
    if (status !== 'published') throw new RelayError(status);
    return { ok: true };
  });

  app.get('/v1/descriptor/:aceId', async (req: FastifyRequest) => {
    const { aceId } = req.params as { aceId: string };
    if (!isACEId(aceId)) throw new RelayError('unknown_peer');
    const agent = await descriptors.get(aceId, clock());
    if (agent?.descriptor.visibility !== 'public') throw new RelayError('unknown_peer');
    return agent;
  });

  // Any permit failure is unknown_peer: the endpoint never reveals whether a private identity exists.
  app.post('/v1/descriptor/resolve', { schema: resolveSchema }, async (req: FastifyRequest) => {
    const { aceId: target, permit } = req.body as { aceId: string; permit: unknown };
    if (!isACEId(target)) throw new RelayError('invalid_argument', 'aceId must be an ACE ID');
    const now = clock();
    const identity = await identityStore.read(target);
    const subject = identity && permittedSubject(identity, permit, undefined, now);
    if (!subject) throw new RelayError('unknown_peer');
    if (await blocks.isBlocked(target, subject)) throw new RelayError('unknown_peer');
    const agent = await descriptors.get(target, now);
    if (!agent) throw new RelayError('unknown_peer');
    return agent;
  });

  app.get('/v1/handles/:handle', async (req: FastifyRequest) => {
    const { handle } = req.params as { handle: string };
    if (!isHandle(handle)) throw new RelayError('unknown_peer');
    const agent = await descriptors.resolveHandle(handle, clock());
    if (!agent) throw new RelayError('unknown_peer');
    return agent;
  });

  app.get('/v1/descriptors', { schema: directorySchema }, async (req: FastifyRequest) => {
    await enforceRate(rateLimiter, `directory:${clientOf(req)}`, config.discoverRateLimit, 60, 'network');
    const q = req.query as { profile?: string; cursor?: string; limit?: number };
    if (q.cursor !== undefined && !isACEId(q.cursor)) throw new RelayError('invalid_argument', 'invalid cursor');
    return descriptors.discover(q.cursor, q.limit ?? DEFAULT_PAGE_LIMIT, q.profile, clock());
  });

  app.post('/v1/blocks', { schema: blockSchema }, async (req: FastifyRequest) => {
    const { peer, blocked, revision } = req.body as { peer: string; blocked: boolean; revision: number };
    if (!isACEId(peer)) throw new RelayError('invalid_argument', 'peer must be an ACE ID');
    const { identity } = await authenticate(deps, req, { action: 'block', peer, blocked, revision });
    if (peer === identity.aceId) throw new RelayError('invalid_argument', 'cannot block yourself');
    const status = await blocks.set(identity.aceId, peer, blocked, revision, identity.lastHash);
    if (status === 'rate_limited' || status === 'relay_busy') throw storageRefusal(status);
    if (status !== 'ok') throw new RelayError(status);
    return { ok: true };
  });
}
