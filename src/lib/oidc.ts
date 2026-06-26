import crypto from 'node:crypto';
import { secret } from '@/lib/crypto';
import { createToken, parseToken } from '@/lib/jwt';

export interface OidcConfig {
  enabled: boolean;
  clientId: string;
  clientSecret: string;
  issuer: string;
  authorizationUrl: string;
  tokenUrl: string;
  userinfoUrl: string;
  scope: string;
  buttonText: string;
  groupsClaim: string;
  adminGroups: string[];
  userGroups: string[];
  viewGroups: string[];
}

interface OidcDiscovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
}

interface OidcTokens {
  access_token: string;
  id_token?: string;
  token_type: string;
  expires_in?: number;
}

interface OidcUserInfo {
  sub: string;
  name?: string;
  email?: string;
  preferred_username?: string;
  picture?: string;
  [key: string]: any;
}

export interface OidcState {
  nonce: string;
  redirectUrl: string;
}

function getBaseUrl(request: Request): string {
  const url = new URL(request.url);
  return `${url.protocol}//${url.host}`;
}

function isConfigured(): boolean {
  return (
    !!process.env.OIDC_CLIENT_ID &&
    !!process.env.OIDC_CLIENT_SECRET &&
    !!(process.env.OIDC_ISSUER || process.env.OIDC_AUTHORIZATION_URL)
  );
}

export function getOidcConfig(): OidcConfig {
  return {
    enabled: isConfigured(),
    clientId: process.env.OIDC_CLIENT_ID || '',
    clientSecret: process.env.OIDC_CLIENT_SECRET || '',
    issuer: process.env.OIDC_ISSUER || '',
    authorizationUrl: process.env.OIDC_AUTHORIZATION_URL || '',
    tokenUrl: process.env.OIDC_TOKEN_URL || '',
    userinfoUrl: process.env.OIDC_USERINFO_URL || '',
    scope: process.env.OIDC_SCOPE || 'openid email profile',
    buttonText: process.env.OIDC_BUTTON_TEXT || 'Login with SSO',
    groupsClaim: process.env.OIDC_GROUPS_CLAIM || '',
    adminGroups: (process.env.OIDC_ADMIN_GROUPS || '')
      .split(',')
      .map(g => g.trim())
      .filter(Boolean),
    userGroups: (process.env.OIDC_USER_GROUPS || '')
      .split(',')
      .map(g => g.trim())
      .filter(Boolean),
    viewGroups: (process.env.OIDC_VIEW_GROUPS || '')
      .split(',')
      .map(g => g.trim())
      .filter(Boolean),
  };
}

/**
 * Resolve a dot-notation path against an object.
 * Example: getClaimValue({ realm_access: { roles: ['admin'] } }, 'realm_access.roles') => ['admin']
 */
export function getClaimValue(obj: Record<string, any>, path: string): any {
  if (!path) {
    return undefined;
  }
  const parts = path.split('.');
  let current = obj;
  for (const part of parts) {
    if (current == null || typeof current !== 'object') {
      return undefined;
    }
    current = current[part];
  }
  return current;
}

/**
 * Determine the Umami role from the user's OIDC groups.
 * Checks in priority order: admin → user → view-only.
 * Returns null if no groups match — caller should reject the login.
 */
export function getRoleFromGroups(userInfo: Record<string, any>, config: OidcConfig): string | null {
  if (!config.groupsClaim) {
    return 'user';
  }

  const userGroups: string[] = getClaimValue(userInfo, config.groupsClaim) || [];

  if (!Array.isArray(userGroups)) {
    return null;
  }

  if (config.adminGroups.length && userGroups.some(g => config.adminGroups.includes(g))) {
    return 'admin';
  }
  if (config.userGroups.length && userGroups.some(g => config.userGroups.includes(g))) {
    return 'user';
  }
  if (config.viewGroups.length && userGroups.some(g => config.viewGroups.includes(g))) {
    return 'view-only';
  }

  // No match — reject login
  return null;
}

async function discoverOidc(issuer: string): Promise<OidcDiscovery> {
  const url = `${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`;
  const res = await fetch(url);

  if (!res.ok) {
    throw new Error(`OIDC discovery failed: ${res.status} ${res.statusText}`);
  }

  return res.json();
}

export async function getAuthorizationUrl(
  request: Request,
): Promise<{ url: string; state: string }> {
  const config = getOidcConfig();
  const baseUrl = getBaseUrl(request);
  const redirectUri = `${baseUrl}/api/auth/oidc/callback`;

  let authorizationUrl = config.authorizationUrl;
  let tokenUrl = config.tokenUrl;
  let userinfoUrl = config.userinfoUrl;

  // Auto-discover if issuer is set and no manual URLs
  if (config.issuer && (!authorizationUrl || !tokenUrl)) {
    const discovery = await discoverOidc(config.issuer);
    authorizationUrl = authorizationUrl || discovery.authorization_endpoint;
    tokenUrl = tokenUrl || discovery.token_endpoint;
    userinfoUrl = userinfoUrl || discovery.userinfo_endpoint;
  }

  if (!authorizationUrl) {
    throw new Error('OIDC authorization URL is not configured');
  }

  // Generate state and nonce
  const nonce = crypto.randomBytes(16).toString('hex');
  const redirectUrl = '/';
  const statePayload: OidcState = { nonce, redirectUrl };
  const state = createToken(statePayload, secret(), { expiresIn: '10m' });

  const params = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: config.scope,
    state,
    nonce,
  });

  return {
    url: `${authorizationUrl}?${params.toString()}`,
    state,
  };
}

export async function exchangeCode(
  request: Request,
  code: string,
): Promise<{ tokens: OidcTokens; userInfo: OidcUserInfo }> {
  const config = getOidcConfig();
  const baseUrl = getBaseUrl(request);
  const redirectUri = `${baseUrl}/api/auth/oidc/callback`;

  let tokenUrl = config.tokenUrl;

  // Auto-discover if needed
  if (config.issuer && !tokenUrl) {
    const discovery = await discoverOidc(config.issuer);
    tokenUrl = discovery.token_endpoint;
  }

  if (!tokenUrl) {
    throw new Error('OIDC token URL is not configured');
  }

  console.log('[oidc] POST token endpoint:', tokenUrl);

  // Exchange code for tokens
  const tokenRes = await fetch(tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: config.clientId,
      client_secret: config.clientSecret,
    }),
  });

  if (!tokenRes.ok) {
    const body = await tokenRes.text();
    throw new Error(`Token exchange failed: ${tokenRes.status} ${body}`);
  }

  const tokens: OidcTokens = await tokenRes.json();

  // Get user info
  let userInfo: OidcUserInfo;
  let userinfoUrl = config.userinfoUrl;

  if (config.issuer && !userinfoUrl) {
    const discovery = await discoverOidc(config.issuer);
    userinfoUrl = discovery.userinfo_endpoint;
  }

  if (userinfoUrl) {
    const userinfoRes = await fetch(userinfoUrl, {
      headers: {
        Authorization: `${tokens.token_type} ${tokens.access_token}`,
        Accept: 'application/json',
      },
    });

    if (!userinfoRes.ok) {
      throw new Error(`Userinfo request failed: ${userinfoRes.status}`);
    }

    userInfo = await userinfoRes.json();
  } else if (tokens.id_token) {
    // Decode ID token payload (without verification, since userinfo is preferred)
    const parts = tokens.id_token.split('.');
    if (parts.length === 3) {
      userInfo = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    }
  }

  if (!userInfo || !userInfo.sub) {
    throw new Error('Unable to get user info from OIDC provider');
  }

  return { tokens, userInfo };
}

export function validateState(state: string, nonce: string): OidcState | null {
  try {
    console.log('[oidc] validateState: parsing token...');
    const s = secret();
    console.log('[oidc] validateState: secret computed');
    const payload = parseToken(state, s) as OidcState & { iat?: number; exp?: number };
    console.log('[oidc] validateState: token parsed, payload:', !!payload);

    if (!payload || !payload.nonce) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

export function getOidcProviderName(): string {
  const config = getOidcConfig();

  if (config.issuer) {
    try {
      const url = new URL(config.issuer);
      return url.hostname;
    } catch {
      return config.issuer;
    }
  }

  return 'oidc';
}
