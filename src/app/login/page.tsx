import type { Metadata } from 'next';
import { LoginPage } from './LoginPage';

export const dynamic = 'force-dynamic';

export default async function () {
  if (process.env.CLOUD_MODE) {
    return null;
  }

  // DISABLE_LOGIN fully blocks access to the login page.
  if (process.env.DISABLE_LOGIN === 'true') {
    return null;
  }

  const manualLoginDisabled = process.env.DISABLE_MANUAL_LOGIN === 'true';

  return <LoginPage allowManualLogin={!manualLoginDisabled} />;
}

export const metadata: Metadata = {
  title: 'Login',
};
