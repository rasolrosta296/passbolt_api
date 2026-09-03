<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Service\Oidc;

use Cake\Cache\Cache;
use Cake\Cache\Engine\ArrayEngine;
use Cake\TestSuite\TestCase;
use Passbolt\KeycloakSso\Error\Exception\OidcNetworkException;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;
use Passbolt\KeycloakSso\Service\Oidc\OidcDiscoveryService;
use Passbolt\KeycloakSso\Service\Oidc\OidcMetadataCache;
use Passbolt\KeycloakSso\Test\Utility\QueuedOidcHttpClient;

final class OidcDiscoveryServiceTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        if (Cache::getConfig('default') === null) {
            Cache::setConfig('default', ['className' => ArrayEngine::class]);
        }
        Cache::clear('default');
    }

    public function testAcceptsStrictDiscoveryDocument(): void
    {
        $service = $this->service($this->validDocument());

        $document = $service->get(true);

        $this->assertSame('https://keyclock.gobaz.ir/realms/passbolt', $document->issuer);
        $this->assertStringEndsWith('/certs', $document->jwksUri);
    }

    public function testRejectsDiscoveryIssuerMismatch(): void
    {
        $document = $this->validDocument();
        $document['issuer'] = 'https://keyclock.gobaz.ir/realms/other';

        $this->expectException(OidcNetworkException::class);
        $this->service($document)->get(true);
    }

    public function testRejectsDiscoveryEndpointOnAnotherOrigin(): void
    {
        $document = $this->validDocument();
        $document['jwks_uri'] = 'https://evil.example/jwks';

        $this->expectException(OidcNetworkException::class);
        $this->service($document)->get(true);
    }

    public function testRejectsDiscoveryWithoutPkceS256(): void
    {
        $document = $this->validDocument();
        $document['code_challenge_methods_supported'] = ['plain'];

        $this->expectException(OidcNetworkException::class);
        $this->service($document)->get(true);
    }

    /** @param array<string, mixed> $document */
    private function service(array $document): OidcDiscoveryService
    {
        $configuration = $this->configuration();

        return new OidcDiscoveryService(
            $configuration,
            new QueuedOidcHttpClient([$document]),
            new OidcMetadataCache()
        );
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

    /** @return array<string, mixed> */
    private function validDocument(): array
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
