import { type NextRequest, NextResponse } from 'next/server';
import { matchesConfiguredPath } from '@/lib/match-configured-path';

export const config = {
  matcher: '/:path*',
};

const TRACKER_PATH = '/script.js';
const COLLECT_PATH = '/api/send';
const LOGIN_PATH = '/login';
const OIDC_PATH = '/api/auth/oidc';
const BASE_PATH = process.env.BASE_PATH || '';

function isOidcConfigured() {
  return (
    !!process.env.OIDC_CLIENT_ID &&
    !!process.env.OIDC_CLIENT_SECRET &&
    !!(process.env.OIDC_ISSUER || process.env.OIDC_AUTHORIZATION_URL)
  );
}

const apiHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': '*',
  'Access-Control-Allow-Methods': 'GET, DELETE, POST, PUT',
  'Access-Control-Max-Age': process.env.CORS_MAX_AGE || '86400',
  'Cache-Control': 'no-cache',
};

const trackerHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Cache-Control': 'public, max-age=86400, must-revalidate',
};

function customCollectEndpoint(request: NextRequest) {
  const collectEndpoint = process.env.COLLECT_API_ENDPOINT;

  if (collectEndpoint) {
    const url = request.nextUrl.clone();

    if (matchesConfiguredPath(url.pathname, collectEndpoint, BASE_PATH)) {
      url.pathname = COLLECT_PATH;
      return NextResponse.rewrite(url, { headers: apiHeaders });
    }
  }
}

function customScriptName(request: NextRequest) {
  const scriptName = process.env.TRACKER_SCRIPT_NAME;

  if (scriptName) {
    const url = request.nextUrl.clone();
    const entries = scriptName.split(',').map(name => name.trim());

    for (const entry of entries) {
      // If the entry is a full URL, extract the pathname and rewrite to the external URL
      if (/^https?:\/\//i.test(entry)) {
        let entryPathname: string;
        try {
          entryPathname = new URL(entry).pathname;
        } catch {
          continue;
        }
        if (matchesConfiguredPath(url.pathname, entryPathname, BASE_PATH)) {
          return NextResponse.rewrite(entry, { headers: trackerHeaders });
        }
      } else {
        // Legacy behavior: rewrite matching name to /script.js
        const name = entry.replace(/^\/+/, '');
        if (matchesConfiguredPath(url.pathname, name, BASE_PATH)) {
          url.pathname = TRACKER_PATH;
          return NextResponse.rewrite(url, { headers: trackerHeaders });
        }
      }
    }
  }
}

function customScriptUrl(request: NextRequest) {
  const scriptUrl = process.env.TRACKER_SCRIPT_URL;

  if (scriptUrl && matchesConfiguredPath(request.nextUrl.pathname, TRACKER_PATH, BASE_PATH)) {
    return NextResponse.rewrite(scriptUrl, { headers: trackerHeaders });
  }
}

function disableLogin(request: NextRequest) {
  const loginDisabled = process.env.DISABLE_LOGIN === 'true';
  const manualLoginDisabled = process.env.DISABLE_MANUAL_LOGIN === 'true';
  const oidcConfigured = isOidcConfigured();

  // Always allow OIDC API routes through (login initiation + callback)
  if (oidcConfigured && matchesConfiguredPath(request.nextUrl.pathname, OIDC_PATH, BASE_PATH)) {
    return;
  }

  if (loginDisabled && matchesConfiguredPath(request.nextUrl.pathname, LOGIN_PATH, BASE_PATH)) {
    return new NextResponse('Access denied', { status: 403 });
  }

  // DISABLE_MANUAL_LOGIN hides the form but keeps the page accessible for the OIDC button.
  // No blocking needed here — the page component handles hiding the form,
  // and the login API rejects credential-based requests.
}

export default function middleware(req: NextRequest) {
  const fns = [customCollectEndpoint, customScriptName, customScriptUrl, disableLogin];

  for (const fn of fns) {
    const res = fn(req);
    if (res) {
      return res;
    }
  }

  return NextResponse.next();
}
