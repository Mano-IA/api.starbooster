import Fastify from 'fastify';
import fetch from 'node-fetch';
import crypto from 'crypto';
import { URL } from 'url';

const fastify = Fastify();

const {
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_REDIRECT_URI,
  BOLT_API_URL,
  BOLT_API_KEY,
} = process.env;

const OAUTH_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const OAUTH_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const SCOPE = 'https://www.googleapis.com/auth/business.manage';

function signState(tenantId) {
  const nonce = crypto.randomBytes(8).toString('hex');
  return JSON.stringify({ tenantId, nonce, t: Date.now() });
}

function parseState(state) {
  try { return JSON.parse(state); }
  catch { return null; }
}

fastify.get('/oauth/google/start', async (req, reply) => {
  const tenantId = req.query.tenant_id;
  if (!tenantId) return reply.code(400).send({ error: 'tenant_id requerido' });

  const state = signState(tenantId);
  const url = new URL(OAUTH_AUTH_URL);
  url.searchParams.set('client_id', GOOGLE_CLIENT_ID);
  url.searchParams.set('redirect_uri', GOOGLE_REDIRECT_URI);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', SCOPE);
  url.searchParams.set('access_type', 'offline');
  url.searchParams.set('include_granted_scopes', 'true');
  url.searchParams.set('prompt', 'consent');
  url.searchParams.set('state', state);

  return reply.redirect(url.toString());
});

fastify.get('/oauth/google/callback', async (req, reply) => {
  const { code, state, error } = req.query;

  if (error) return reply.code(400).send({ error });
  if (!code || !state) return reply.code(400).send({ error: 'code/state faltantes' });

  const parsed = parseState(state);
  if (!parsed?.tenantId) return reply.code(400).send({ error: 'state inválido' });
  const tenantId = parsed.tenantId;

  const tokenRes = await fetch(OAUTH_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id: GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      redirect_uri: GOOGLE_REDIRECT_URI,
      grant_type: 'authorization_code',
    }),
  });

  if (!tokenRes.ok) {
    const txt = await tokenRes.text();
    return reply.code(502).send({ error: 'token_exchange_failed', detail: txt });
  }

  const tokens = await tokenRes.json();
  const accessToken = tokens.access_token;
  const refreshToken = tokens.refresh_token;
  const expiresIn = tokens.expires_in;
  const expiryISO = new Date(Date.now() + (expiresIn || 0) * 1000).toISOString();

  const saveRes = await fetch(`${BOLT_API_URL}/tenant-settings/${tenantId}`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${BOLT_API_KEY}`,
    },
    body: JSON.stringify({
      google_access_token: accessToken,
      ...(refreshToken ? { google_refresh_token: refreshToken } : {}),
      google_token_expiry: expiryISO,
    }),
  });

  if (!saveRes.ok) {
    const txt = await saveRes.text();
    return reply.code(502).send({ error: 'bolt_update_failed', detail: txt });
  }

  return reply.redirect('/settings?google=connected');
});

fastify.get('/health', async () => ({ ok: true }));

export default async function handler(req, res) {
  await fastify.ready();
  fastify.server.emit('request', req, res);
}
