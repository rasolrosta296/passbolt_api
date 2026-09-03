<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Utility\Http;

use Cake\TestSuite\TestCase;
use Passbolt\KeycloakSso\Error\Exception\OidcNetworkException;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;
use Passbolt\KeycloakSso\Utility\Http\SafeOidcHttpClient;
use PHPUnit\Framework\Attributes\DataProvider;
use Passbolt\KeycloakSso\Test\Utility\StaticHostResolver;

final class SafeOidcHttpClientTest extends TestCase
{
    public function testAcceptsExactOriginResolvingToPublicAddress(): void
    {
        $client = new SafeOidcHttpClient($this->configuration(), null, new StaticHostResolver(['203.0.113.10']));

        $client->assertSafeUrl('https://keyclock.gobaz.ir/realms/passbolt/protocol/openid-connect/certs');
        $this->addToAssertionCount(1);
    }

    public function testRejectsHttpEndpoint(): void
    {
        $client = new SafeOidcHttpClient($this->configuration(), null, new StaticHostResolver(['203.0.113.10']));

        $this->expectException(OidcNetworkException::class);
        $client->assertSafeUrl('http://keyclock.gobaz.ir/realms/passbolt');
    }

    public function testRejectsUnexpectedOrigin(): void
    {
        $client = new SafeOidcHttpClient($this->configuration(), null, new StaticHostResolver(['203.0.113.10']));

        $this->expectException(OidcNetworkException::class);
        $client->assertSafeUrl('https://evil.example/jwks');
    }

    #[DataProvider('unsafeAddressProvider')]
    public function testRejectsUnsafeDestination(string $address): void
    {
        $client = new SafeOidcHttpClient($this->configuration(), null, new StaticHostResolver([$address]));

        $this->expectException(OidcNetworkException::class);
        $client->assertSafeUrl('https://keyclock.gobaz.ir/realms/passbolt');
    }

    public static function unsafeAddressProvider(): array
    {
        return [
            'IPv4 loopback' => ['127.0.0.1'],
            'IPv4 private' => ['10.0.0.1'],
            'IPv4 link local' => ['169.254.1.1'],
            'IPv6 loopback' => ['::1'],
            'IPv6 unique local' => ['fd00::1'],
            'IPv6 link local' => ['fe80::1'],
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
