<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Service\Oidc;

use Cake\Cache\Cache;
use Cake\Cache\Engine\ArrayEngine;
use Cake\TestSuite\TestCase;
use Passbolt\KeycloakSso\Error\Exception\OidcNetworkException;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;
use Passbolt\KeycloakSso\Service\Oidc\JwksProvider;
use Passbolt\KeycloakSso\Service\Oidc\OidcDiscoveryService;
use Passbolt\KeycloakSso\Service\Oidc\OidcMetadataCache;
use Passbolt\KeycloakSso\Test\Utility\QueuedOidcHttpClient;

final class JwksProviderTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        if (Cache::getConfig('default') === null) {
            Cache::setConfig('default', ['className' => ArrayEngine::class]);
        }
        Cache::clear('default');
    }

    public function testAcceptsRs256SigningKey(): void
    {
        $key = $this->validKey('signing-key');

        $this->assertSame(['keys' => [$key]], $this->provider(['keys' => [$key]])->get(true));
    }

    public function testExcludesRsaEncryptionKeyAlongsideRs256SigningKey(): void
    {
        $signingKey = $this->validKey('signing-key');
        $encryptionKey = [
            'kty' => 'RSA',
            'kid' => 'encryption-key',
            'use' => 'enc',
            'alg' => 'RSA-OAEP',
            'n' => str_repeat('B', 342),
            'e' => 'AQAB',
        ];

        $result = $this->provider(['keys' => [$encryptionKey, $signingKey]])->get(true);

        $this->assertSame(['keys' => [$signingKey]], $result);
    }

    public function testExcludesUnrelatedKeysAlongsideRs256SigningKey(): void
    {
        $signingKey = $this->validKey('signing-key');
        $ecKey = [
            'kty' => 'EC',
            'kid' => 'ec-signing-key',
            'use' => 'sig',
            'alg' => 'ES256',
        ];
        $rsaRs512Key = [
            'kty' => 'RSA',
            'kid' => 'rsa-rs512-key',
            'use' => 'sig',
            'alg' => 'RS512',
        ];

        $result = $this->provider(['keys' => [$ecKey, $rsaRs512Key, $signingKey]])->get(true);

        $this->assertSame(['keys' => [$signingKey]], $result);
    }

    public function testRejectsJwksWithoutEligibleVerificationKey(): void
    {
        $provider = $this->provider(['keys' => [[
            'kty' => 'RSA',
            'kid' => 'encryption-key',
            'use' => 'enc',
            'alg' => 'RSA-OAEP',
        ]]]);

        $this->expectException(OidcNetworkException::class);
        $provider->get(true);
    }

    public function testRejectsDuplicateKeyIds(): void
    {
        $key = $this->validKey('one');
        $provider = $this->provider(['keys' => [$key, $key]]);

        $this->expectException(OidcNetworkException::class);
        $provider->get(true);
    }

    public function testRejectsMalformedJwks(): void
    {
        $key = $this->validKey('one');
        $key['n'] = 'too-short';
        $provider = $this->provider(['keys' => [$key]]);

        $this->expectException(OidcNetworkException::class);
        $provider->get(true);
    }

    public function testRejectsCandidateKeyOpsWithoutVerify(): void
    {
        $key = $this->validKey('one');
        $key['key_ops'] = ['encrypt'];
        $provider = $this->provider(['keys' => [$key]]);

        $this->expectException(OidcNetworkException::class);
        $provider->get(true);
    }

    public function testAcceptsJwksRotationOnForcedRefresh(): void
    {
        $provider = $this->provider(
            ['keys' => [$this->validKey('old')]],
            ['keys' => [$this->validKey('new')]]
        );

        $this->assertSame('old', $provider->get(true)['keys'][0]['kid']);
        $this->assertSame('new', $provider->get(true)['keys'][0]['kid']);
    }

    /** @param array{keys: list<array<string, mixed>>} ...$jwks */
    private function provider(array ...$jwks): JwksProvider
    {
        $configuration = $this->configuration();
        $cache = new OidcMetadataCache();
        $discoveryClient = new QueuedOidcHttpClient([$this->validDiscovery(), $this->validDiscovery()]);
        $jwksClient = new QueuedOidcHttpClient($jwks);
        $discovery = new OidcDiscoveryService($configuration, $discoveryClient, $cache);

        return new JwksProvider($configuration, $discovery, $jwksClient, $cache);
    }

    /** @return array<string, mixed> */
    private function validKey(string $kid): array
    {
        return [
            'kty' => 'RSA',
            'kid' => $kid,
            'use' => 'sig',
            'alg' => 'RS256',
            'n' => str_repeat('A', 342),
            'e' => 'AQAB',
        ];
    }

    /** @return array<string, mixed> */
    private function validDiscovery(): array
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

    private function configuration(): OidcConfigurationDto
    {
        return new OidcConfigurationDto(
            'https://keyclock.gobaz.ir/realms/passbolt',
            'passbolt',
            'secret',
            'https://passbolt.gobaz.ir/auth/keycloak/callback',
            random_bytes(32)
        );
    }
}
