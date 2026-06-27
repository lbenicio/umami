import { hash, secret, uuid } from '@/lib/crypto';
import { saveAuth } from '@/lib/auth';
import { createSecureToken } from '@/lib/jwt';
import { exchangeCode, getOidcConfig, getOidcProviderName, getRoleFromGroups, validateState } from '@/lib/oidc';
import { hashPassword } from '@/lib/password';
import prisma from '@/lib/prisma';
import redis from '@/lib/redis';
import { badRequest, serverError } from '@/lib/response';
import { getAllUserTeams, getUserByOidc, getUserByUsername } from '@/queries/prisma';

export async function GET(request: Request) {
  const config = getOidcConfig();

  if (!config.enabled) {
    return badRequest({ message: 'OIDC is not enabled' });
  }

  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const error = url.searchParams.get('error');
  const errorDescription = url.searchParams.get('error_description');

  if (error) {
    return badRequest({ message: `OIDC error: ${errorDescription || error}` });
  }

  if (!code || !state) {
    return badRequest({ message: 'Missing code or state parameter' });
  }

  try {
    // Exchange code for tokens and get user info
    console.log('[oidc] Exchanging code...');
    const { userInfo } = await exchangeCode(request, code);
    console.log('[oidc] Got userInfo:', Object.keys(userInfo));
    console.log('[oidc] userInfo.sub:', userInfo.sub);
    if (userInfo.groups) console.log('[oidc] userInfo.groups:', userInfo.groups);

    // Validate state (CSRF protection)
    console.log('[oidc] Validating state...');
    const stateData = validateState(state, '');
    console.log('[oidc] State valid:', !!stateData);
    if (!stateData) {
      return badRequest({ message: 'Invalid state parameter' });
    }

    const { sub } = userInfo;
    const provider = getOidcProviderName();
    console.log('[oidc] sub:', sub, 'provider:', provider);

    if (!sub) {
      return badRequest({ message: 'No sub claim in user info' });
    }

    // Determine role from groups. Reject if no role matches.
    const mappedRole = getRoleFromGroups(userInfo, config);
    console.log('[oidc] Mapped role:', mappedRole);

    if (!mappedRole) {
      return badRequest({ message: 'User does not belong to any authorized role group' });
    }

    // Find or create user
    console.log('[oidc] Looking up user by OIDC...');
    let user: { id: string; username: string; password: string; role: string; createdAt?: Date } | null = await getUserByOidc(sub, provider);
    console.log('[oidc] User found:', user ? user.id : 'null, will create');

    if (!user) {
      // Try to find by email/username
      let username = userInfo.preferred_username || userInfo.email || `oidc_${sub}`;

      if (userInfo.email) {
        user = await getUserByUsername(userInfo.email, { includePassword: true });
      }

      if (!user && userInfo.preferred_username) {
        user = await getUserByUsername(userInfo.preferred_username, { includePassword: true });
      }

      if (!user) {
        // Ensure username is unique by appending random suffix if needed
        const existingUser = await getUserByUsername(username);
        if (existingUser) {
          username = `${username}_${sub.substring(0, 8)}`;
        }

        // Create a new user with OIDC fields
        const userId = uuid();
        const randomPassword = hashPassword(sub + Date.now().toString());

        console.log('[oidc] Creating user with role:', mappedRole);

        await prisma.client.user.create({
          data: {
            id: userId,
            username: username.toLowerCase(),
            password: randomPassword,
            role: mappedRole,
            oidcId: sub,
            oidcProvider: provider,
          },
        });

        user = {
          id: userId,
          username,
          password: randomPassword,
          role: mappedRole,
        };
      } else {
        // Link existing user to OIDC and update role from groups
        console.log('[oidc] Linking existing user, updating role to:', mappedRole);
        await prisma.client.user.update({
          where: { id: user.id },
          data: {
            oidcId: sub,
            oidcProvider: provider,
            role: mappedRole,
          },
        });
        user.role = mappedRole;
      }
    } else {
      // Update role on each login to reflect current group membership
      console.log('[oidc] Updating existing user role to:', mappedRole);
      await prisma.client.user.update({
        where: { id: user.id },
        data: { role: mappedRole },
      });
      user.role = mappedRole;
    }

    // Generate auth token
    console.log('[oidc] Generating auth token...');
    const pwd = hash(user.password);
    console.log('[oidc] Password hash computed');

    let token: string;

    console.log('[oidc] Redis enabled:', redis.enabled);
    if (redis.enabled) {
      console.log('[oidc] Saving auth to Redis...');
      token = await saveAuth({ userId: user.id, role: user.role, pwd });
      console.log('[oidc] Auth saved to Redis');
    } else {
      console.log('[oidc] Creating secure token...');
      token = createSecureToken({ userId: user.id, role: user.role, pwd }, secret());
      console.log('[oidc] Secure token created');
    }

    console.log('[oidc] Fetching teams...');
    const teams = await getAllUserTeams(user.id);
    console.log('[oidc] Teams fetched:', teams?.length || 0);

    // Redirect to SSO page with token
    const redirectUrl = stateData.redirectUrl || '/';
    const ssoParams = new URLSearchParams({
      token,
      url: redirectUrl,
    });

    const ssoUrl = `/sso?${ssoParams.toString()}`;
    const base = process.env.APP_URL || request.url;
    console.log('[oidc] Redirecting to:', new URL(ssoUrl, base).toString().slice(0, 80), '...');

    return Response.redirect(new URL(ssoUrl, base));
  } catch (error: any) {
    console.log('[oidc] ERROR:', error.message || error);
    return serverError(error.message || 'OIDC callback failed');
  }
}
