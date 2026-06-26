'use client';
import { Column, Loading } from '@umami/react-zen';
import { useRouter } from 'next/navigation';
import { useEffect } from 'react';
import { useConfig, useLoginQuery } from '@/components/hooks';
import { LoginForm } from './LoginForm';

export function LoginPage({ allowManualLogin = true }: { allowManualLogin?: boolean }) {
  const { user, isLoading } = useLoginQuery();
  const config = useConfig();
  const router = useRouter();

  useEffect(() => {
    if (user) {
      router.replace('/');
    }
  }, [user, router]);

  if (isLoading || user) {
    return <Loading placement="absolute" />;
  }

  const oidcEnabled = config?.oidcEnabled || false;

  return (
    <Column
      alignItems="center"
      justifyContent="flex-start"
      height="100vh"
      backgroundColor="surface-raised"
      style={{ paddingTop: '15vh' }}
    >
      <LoginForm
        allowManualLogin={allowManualLogin}
        oidcEnabled={oidcEnabled}
        oidcButtonText={config?.oidcButtonText || 'Login with SSO'}
      />
    </Column>
  );
}
