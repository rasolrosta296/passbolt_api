<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Service\Oidc;

use Cake\Cache\Cache;
use Cake\Cache\Engine\ArrayEngine;
use Cake\TestSuite\TestCase;
use Passbolt\KeycloakSso\Error\Exception\OidcNetworkException;
use Passbolt\KeycloakSso\Error\Exception\OidcValidationException;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;
use Passbolt\KeycloakSso\Service\Oidc\AuthorizationCodeExchangeService;
use Passbolt\KeycloakSso\Service\Oidc\OidcDiscoveryService;
use Passbolt\KeycloakSso\Service\Oidc\OidcMetadataCache;
use Passbolt\KeycloakSso\Test\Utility\FailingOidcHttpClient;
use Passbolt\KeycloakSso\Test\Utility\QueuedOidcHttpClient;
use Passbolt\KeycloakSso\Test\Utility\RecordingOidcHttpClient;

final class AuthorizationCodeExchangeServiceTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        if (Cache::getConfig('default') === null) {
            Cache::setConfig('default', ['className' => ArrayEngine::class]);
        }
        Cache::clear('default');
    }

    public function testExchangesCodeWithExactRedirectAndPkce(): void
    {
        $configuration = $this->configuration();
        $cache = new OidcMetadataCache();
        $discovery = new OidcDiscoveryService(
            $configuration,
            new QueuedOidcHttpClient([$this->discovery()]),
            $cache
        );
        $tokenClient = new RecordingOidcHttpClient(['id_token' => 'header.payload.signature']);
        $service = new AuthorizationCodeExchangeService($configuration, $discovery, $tokenClient);

        $this->assertSame('header.payload.signature', $service->exchange('one-time-code', 'pkce-verifier'));
        $this->assertSame('POST', $tokenClient->method);
        $this->assertSame($configuration->redirectUri, $tokenClient->form['redirect_uri']);
        $this->assertSame('pkce-verifier', $tokenClient->form['code_verifier']);
        $this->assertSame('one-time-code', $tokenClient->form['code']);
        $this->assertSame($configuration->clientSecret, $tokenClient->form['client_secret']);
    }

    public function testRejectsMalformedCallbackCode(): void
    {
        $configuration = $this->configuration();
        $discovery = new OidcDiscoveryService(
            $configuration,
            new QueuedOidcHttpClient([$this->discovery()]),
            new OidcMetadataCache()
        );
        $service = new AuthorizationCodeExchangeService(
            $configuration,
            $discovery,
            new RecordingOidcHttpClient([])
        );

        $this->expectException(OidcValidationException::class);
        $service->exchange("code\nvalue", 'pkce-verifier');
    }

    public function testPropagatesTokenEndpointFailureWithoutResponseData(): void
    {
        $configuration = $this->configuration();
        $discovery = new OidcDiscoveryService(
            $configuration,
            new QueuedOidcHttpClient([$this->discovery()]),
            new OidcMetadataCache()
        );
        $service = new AuthorizationCodeExchangeService($configuration, $discovery, new FailingOidcHttpClient());

        $this->expectException(OidcNetworkException::class);
        $this->expectExceptionMessage('provider request failed');
        $service->exchange('one-time-code', 'pkce-verifier');
    }

    private function configuration(): OidcConfigurationDto
    {
        return new OidcConfigurationDto(
            'https://keyclock.gobaz.ir/realms/passbolt',
            'passbolt',
            'client-secret',
            'https://passbolt.gobaz.ir/auth/keycloak/callback',
            random_bytes(32)
        );
    }

    /** @return array<string, mixed> */
    private function discovery(): array
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
}
