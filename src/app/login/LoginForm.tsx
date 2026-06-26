import {
  Column,
  Form,
  FormButtons,
  FormField,
  FormSubmitButton,
  Heading,
  Icon,
  PasswordField,
  TextField,
  Button,
  Text,
} from '@umami/react-zen';
import { useRouter } from 'next/navigation';
import { useMessages, useUpdateQuery } from '@/components/hooks';
import { Logo } from '@/components/svg';
import { setClientAuthToken } from '@/lib/client';
import { setUser } from '@/store/app';

export function LoginForm({
  allowManualLogin = true,
  oidcEnabled = false,
  oidcButtonText = 'Login with SSO',
}: {
  allowManualLogin?: boolean;
  oidcEnabled?: boolean;
  oidcButtonText?: string;
}) {
  const { t, labels, getErrorMessage } = useMessages();
  const router = useRouter();
  const { mutateAsync, error } = useUpdateQuery('/auth/login');

  const handleSubmit = async (data: any) => {
    await mutateAsync(data, {
      onSuccess: async ({ token, user }) => {
        setClientAuthToken(token);
        setUser(user);
        router.push('/');
      },
    });
  };

  const handleOidcLogin = () => {
    window.location.href = `/api/auth/oidc/login`;
  };

  return (
    <Column justifyContent="center" alignItems="center" gap="6">
      <Icon size="lg">
        <Logo />
      </Icon>
      <Heading>umami</Heading>
      {oidcEnabled && (
        <>
          <Button onPress={handleOidcLogin} variant="primary" style={{ minWidth: 300 }}>
            {oidcButtonText}
          </Button>
          {allowManualLogin && (
            <Text style={{ color: 'var(--gray-500)', fontSize: '0.875rem' }}>or</Text>
          )}
        </>
      )}
      {allowManualLogin && (
        <Form onSubmit={handleSubmit} error={getErrorMessage(error)} style={{ minWidth: 300 }}>
          <FormField
            label={t(labels.username)}
            data-test="input-username"
            name="username"
            rules={{ required: t(labels.required) }}
          >
            <TextField autoComplete="username" />
          </FormField>

          <FormField
            label={t(labels.password)}
            data-test="input-password"
            name="password"
            rules={{ required: t(labels.required) }}
          >
            <PasswordField autoComplete="current-password" />
          </FormField>
          <FormButtons>
            <FormSubmitButton
              data-test="button-submit"
              variant="primary"
              style={{ flex: 1 }}
              isDisabled={false}
            >
              {t(labels.login)}
            </FormSubmitButton>
          </FormButtons>
        </Form>
      )}
      {!oidcEnabled && !allowManualLogin && (
        <Text>Login is not available.</Text>
      )}
    </Column>
  );
}
