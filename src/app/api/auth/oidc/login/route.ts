import { getAuthorizationUrl, getOidcConfig } from '@/lib/oidc';
import { badRequest } from '@/lib/response';

export async function GET(request: Request) {
  const config = getOidcConfig();

  if (!config.enabled) {
    return badRequest({ message: 'OIDC is not enabled' });
  }

  try {
    const { url } = await getAuthorizationUrl(request);

    return Response.redirect(url);
  } catch (error: any) {
    return badRequest({ message: error.message || 'Failed to initiate OIDC login' });
  }
}
