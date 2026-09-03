<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Service\Oidc;

use App\Test\Factory\UserFactory;
use Firebase\JWT\JWT;
use OpenSSLAsymmetricKey;
use Passbolt\KeycloakSso\Error\Exception\OidcTransactionException;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;
use Passbolt\KeycloakSso\Service\Identity\ExistingUserDiscoveryService;
use Passbolt\KeycloakSso\Service\Oidc\AuthorizationCodeExchangeService;
use Passbolt\KeycloakSso\Service\Oidc\IdTokenValidationService;
use Passbolt\KeycloakSso\Service\Oidc\OidcCallbackService;
use Passbolt\KeycloakSso\Service\Oidc\OidcDiscoveryService;
use Passbolt\KeycloakSso\Service\Oidc\OidcMetadataCache;
use Passbolt\KeycloakSso\Service\Transaction\ClaimOidcTransactionService;
use Passbolt\KeycloakSso\Service\Transaction\CreateOidcTransactionService;
use Passbolt\KeycloakSso\Service\Transaction\TransactionSecretProtector;
use Passbolt\KeycloakSso\Test\Lib\KeycloakSsoIntegrationTestCase;
use Passbolt\KeycloakSso\Test\Utility\QueuedOidcHttpClient;
use Passbolt\KeycloakSso\Test\Utility\RecordingOidcHttpClient;
use Passbolt\KeycloakSso\Test\Utility\StaticJwksProvider;

final class OidcCallbackServiceTest extends KeycloakSsoIntegrationTestCase
{
    public function testValidCompleteMilestoneFlowProducesOnlyOneTimeResult(): void
    {
        UserFactory::make(['username' => 'user@example.com'])->user()->active()->notDisabled()->persist();
        $configuration = $this->configuration();
        $protector = new TransactionSecretProtector($configuration->transactionEncryptionKey);
        $create = new CreateOidcTransactionService($protector);
        $created = $create->create(
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
        $tokenClient = new RecordingOidcHttpClient(['id_token' => $idToken]);
        $transactions = new ClaimOidcTransactionService($protector);
        $service = new OidcCallbackService(
            $configuration,
            $transactions,
            new AuthorizationCodeExchangeService($configuration, $discovery, $tokenClient),
            new IdTokenValidationService($configuration, new StaticJwksProvider(['keys' => [$jwk]])),
            new ExistingUserDiscoveryService()
        );

        $resultToken = $service->process($created->state, $created->browserBinding, 'one-time-code');

        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $resultToken);
        $this->assertSame($created->pkceVerifier, $tokenClient->form['code_verifier']);
        $this->assertSame('one-time-code', $tokenClient->form['code']);
        $transactions->consumeResult($resultToken);

        $this->expectException(OidcTransactionException::class);
        $transactions->consumeResult($resultToken);
    }

    private function configuration(): OidcConfigurationDto
    {
        return new OidcConfigurationDto(
            'https://keyclock.gobaz.ir/realms/passbolt',
            'passbolt',
            'client-secret-for-tests',
            'https://passbolt.gobaz.ir/auth/keycloak/callback',
            random_bytes(32)
        );
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

    /**
     * @return array<string, mixed>
     */
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
