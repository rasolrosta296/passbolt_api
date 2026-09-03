<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Controller\Oidc;

use App\Test\Factory\AuthenticationTokenFactory;
use App\Test\Factory\UserFactory;
use Firebase\JWT\JWT;
use OpenSSLAsymmetricKey;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;
use Passbolt\KeycloakSso\Service\Identity\ExistingUserDiscoveryService;
use Passbolt\KeycloakSso\Service\Oidc\AuthorizationCodeExchangeService;
use Passbolt\KeycloakSso\Service\Oidc\IdTokenValidationService;
use Passbolt\KeycloakSso\Service\Oidc\OidcCallbackService;
use Passbolt\KeycloakSso\Service\Oidc\OidcCookieService;
use Passbolt\KeycloakSso\Service\Oidc\OidcDiscoveryService;
use Passbolt\KeycloakSso\Service\Oidc\OidcMetadataCache;
use Passbolt\KeycloakSso\Service\Oidc\OidcServiceFactoryInterface;
use Passbolt\KeycloakSso\Service\Transaction\ClaimOidcTransactionService;
use Passbolt\KeycloakSso\Service\Transaction\CreateOidcTransactionService;
use Passbolt\KeycloakSso\Service\Transaction\TransactionSecretProtector;
use Passbolt\KeycloakSso\Test\Lib\KeycloakSsoIntegrationTestCase;
use Passbolt\KeycloakSso\Test\Utility\QueuedOidcHttpClient;
use Passbolt\KeycloakSso\Test\Utility\RecordingOidcHttpClient;
use Passbolt\KeycloakSso\Test\Utility\RecordingOidcResultConsumer;
use Passbolt\KeycloakSso\Test\Utility\StaticAuthorizationRequestProvider;
use Passbolt\KeycloakSso\Test\Utility\StaticJwksProvider;
use Passbolt\KeycloakSso\Test\Utility\StaticOidcServiceFactory;
use Passbolt\KeycloakSso\Test\Utility\SuccessfulOidcCallbackProcessor;

final class CallbackSecurityTest extends KeycloakSsoIntegrationTestCase
{
    public function testSuccessfulOidcProofDoesNotAuthenticatePassboltOrCreateTokens(): void
    {
        $processor = new SuccessfulOidcCallbackProcessor();
        $factory = new StaticOidcServiceFactory(
            new StaticAuthorizationRequestProvider(),
            $processor,
            new RecordingOidcResultConsumer()
        );
        $this->mockService(OidcServiceFactoryInterface::class, static fn () => $factory);
        $state = str_repeat('s', 43);
        $binding = str_repeat('b', 43);
        $code = 'sensitive-authorization-code';
        $tokenCount = AuthenticationTokenFactory::count();
        $this->configRequest(['cookies' => [OidcCookieService::BROWSER_BINDING_COOKIE => $binding]]);

        $this->get('/auth/keycloak/callback?state=' . $state . '&code=' . $code);

        $this->assertResponseCode(303);
        $this->assertRedirect('/auth/keycloak/result.json');
        $this->assertEmpty($this->getSession()->read('Auth.user'));
        $this->assertSame($tokenCount, AuthenticationTokenFactory::count());
        $this->assertSame(['state' => $state, 'binding' => $binding, 'code' => $code], $processor->received);

        $this->getJson('/auth/is-authenticated.json');
        $this->assertAuthenticationError();
        $this->assertEmpty($this->getSession()->read('Auth.user'));
        $this->assertSame($tokenCount, AuthenticationTokenFactory::count());
    }

    public function testRealValidOidcPipelineAndMatchingUserStillDoNotAuthenticatePassbolt(): void
    {
        UserFactory::make(['username' => 'user@example.com'])->user()->active()->notDisabled()->persist();
        $configuration = new OidcConfigurationDto(
            'https://keyclock.gobaz.ir/realms/passbolt',
            'passbolt',
            'client-secret-for-tests',
            'https://passbolt.gobaz.ir/auth/keycloak/callback',
            random_bytes(32)
        );
        $protector = new TransactionSecretProtector($configuration->transactionEncryptionKey);
        $created = (new CreateOidcTransactionService($protector))->create(
            $configuration->issuer,
            $configuration->clientId,
            $configuration->redirectUri,
            $configuration->configurationHash(),
            OidcConfigurationDto::TRANSACTION_TTL_SECONDS
        );
        [$privateKey, $jwk] = $this->signingKey();
        $now = time();
        $idToken = JWT::encode([
            'iss' => $configuration->issuer,
            'aud' => $configuration->clientId,
            'azp' => $configuration->clientId,
            'exp' => $now + 120,
            'iat' => $now,
            'nonce' => $created->nonce,
            'sub' => 'immutable-keycloak-subject',
            'email' => 'user@example.com',
            'email_verified' => true,
        ], $privateKey, 'RS256', 'current-key');
        $discovery = new OidcDiscoveryService(
            $configuration,
            new QueuedOidcHttpClient([$this->discoveryDocument()]),
            new OidcMetadataCache()
        );
        $transactions = new ClaimOidcTransactionService($protector);
        $callback = new OidcCallbackService(
            $configuration,
            $transactions,
            new AuthorizationCodeExchangeService(
                $configuration,
                $discovery,
                new RecordingOidcHttpClient(['id_token' => $idToken])
            ),
            new IdTokenValidationService($configuration, new StaticJwksProvider(['keys' => [$jwk]])),
            new ExistingUserDiscoveryService()
        );
        $factory = new StaticOidcServiceFactory(
            new StaticAuthorizationRequestProvider(),
            $callback,
            $transactions
        );
        $this->mockService(OidcServiceFactoryInterface::class, static fn () => $factory);
        $tokenCount = AuthenticationTokenFactory::count();
        $this->configRequest(['cookies' => [
            OidcCookieService::BROWSER_BINDING_COOKIE => $created->browserBinding,
        ]]);

        $this->get('/auth/keycloak/callback?state=' . $created->state . '&code=one-time-code');

        $this->assertResponseCode(303);
        $this->assertRedirect('/auth/keycloak/result.json');
        $this->assertEmpty($this->getSession()->read('Auth.user'));
        $this->assertSame($tokenCount, AuthenticationTokenFactory::count());

        $this->getJson('/auth/is-authenticated.json');
        $this->assertAuthenticationError();
        $this->assertEmpty($this->getSession()->read('Auth.user'));
        $this->assertSame($tokenCount, AuthenticationTokenFactory::count());
    }

    public function testOneTimeResultContainsOnlyApprovedFields(): void
    {
        $consumer = new RecordingOidcResultConsumer();
        $factory = new StaticOidcServiceFactory(
            new StaticAuthorizationRequestProvider(),
            new SuccessfulOidcCallbackProcessor(),
            $consumer
        );
        $this->mockService(OidcServiceFactoryInterface::class, static fn () => $factory);
        $resultToken = str_repeat('r', 43);
        $this->configRequest(['cookies' => [OidcCookieService::RESULT_COOKIE => $resultToken]]);

        $this->getJson('/auth/keycloak/result.json');

        $this->assertResponseOk();
        $this->assertSame($resultToken, $consumer->consumedToken);
        $this->assertSame([
            'oidc_authenticated' => true,
            'passbolt_user_exists' => true,
            'next_step' => 'passbolt_cryptographic_authentication_required',
        ], (array)$this->_responseJsonBody);
        $body = (string)$this->_response->getBody();
        foreach (['authorization-code', 'state', 'nonce', 'id_token', 'access_token', 'subject', 'email', 'user_id'] as $forbidden) {
            $this->assertStringNotContainsString($forbidden, $body);
        }
        $this->assertSame('no-store', $this->_response->getHeaderLine('Cache-Control'));
        $this->assertSame('no-cache', $this->_response->getHeaderLine('Pragma'));
        $this->assertEmpty($this->getSession()->read('Auth.user'));
    }

    public function testMalformedCallbackRedirectsToFixedGenericFailureWithoutLeakage(): void
    {
        $factory = new StaticOidcServiceFactory(
            new StaticAuthorizationRequestProvider(),
            new SuccessfulOidcCallbackProcessor(),
            new RecordingOidcResultConsumer()
        );
        $this->mockService(OidcServiceFactoryInterface::class, static fn () => $factory);
        $sensitiveCode = 'sensitive-authorization-code';

        $this->get('/auth/keycloak/callback?code=' . $sensitiveCode);

        $this->assertResponseCode(303);
        $this->assertRedirect('/auth/keycloak/error.json');
        $this->assertStringNotContainsString($sensitiveCode, $this->_response->getHeaderLine('Location'));
        $this->assertSame('no-store', $this->_response->getHeaderLine('Cache-Control'));
        $this->assertEmpty($this->getSession()->read('Auth.user'));
    }

    /**
     * @return array{0: \OpenSSLAsymmetricKey, 1: array<string, mixed>}
     */
    private function signingKey(): array
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $key);
        $details = openssl_pkey_get_details($key);
        $this->assertIsArray($details);

        return [$key, [
            'kty' => 'RSA',
            'kid' => 'current-key',
            'use' => 'sig',
            'alg' => 'RS256',
            'n' => self::base64Url($details['rsa']['n']),
            'e' => self::base64Url($details['rsa']['e']),
        ]];
    }

    /** @return array<string, mixed> */
    private function discoveryDocument(): array
    {
        $base = 'https://keyclock.gobaz.ir/realms/passbolt/protocol/openid-connect';

        return [
            'issuer' => 'https://keyclock.gobaz.ir/realms/passbolt',
            'authorization_endpoint' => $base . '/auth',
            'token_endpoint' => $base . '/token',
            'jwks_uri' => $base . '/certs',
            'response_types_supported' => ['code'],
            'scopes_supported' => ['openid', 'email'],
            'id_token_signing_alg_values_supported' => ['RS256'],
            'code_challenge_methods_supported' => ['S256'],
        ];
    }

    private static function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
