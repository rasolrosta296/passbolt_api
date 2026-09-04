<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Configuration;

use Cake\TestSuite\TestCase;
use Passbolt\KeycloakSso\Configuration\KeycloakSsoEnvironment;
use Passbolt\KeycloakSso\Configuration\OidcConfigurationService;
use Passbolt\KeycloakSso\Error\Exception\OidcConfigurationException;

final class OidcConfigurationServiceTest extends TestCase
{
    public function testLoadsStrictConfiguration(): void
    {
        $configuration = (new OidcConfigurationService())->load($this->validEnvironment());

        $this->assertSame('https://keyclock.gobaz.ir/realms/passbolt', $configuration->issuer);
        $this->assertSame('passbolt', $configuration->clientId);
        $this->assertSame('/auth/keycloak/callback', parse_url($configuration->redirectUri, PHP_URL_PATH));
        $this->assertSame(32, strlen($configuration->transactionEncryptionKey));
        $this->assertStringNotContainsString('secret', $configuration->configurationHash());
    }

    public function testRejectsDisabledConfiguration(): void
    {
        $environment = $this->validEnvironment();
        $environment[KeycloakSsoEnvironment::ENABLED] = 'false';

        $this->expectException(OidcConfigurationException::class);
        (new OidcConfigurationService())->load($environment);
    }

    public function testRejectsHttpIssuer(): void
    {
        $environment = $this->validEnvironment();
        $environment[KeycloakSsoEnvironment::ISSUER] = 'http://keyclock.gobaz.ir/realms/passbolt';

        $this->expectException(OidcConfigurationException::class);
        (new OidcConfigurationService())->load($environment);
    }

    public function testRejectsIssuerWithTrailingSlash(): void
    {
        $environment = $this->validEnvironment();
        $environment[KeycloakSsoEnvironment::ISSUER] = 'https://keyclock.gobaz.ir/realms/passbolt/';

        $this->expectException(OidcConfigurationException::class);
        (new OidcConfigurationService())->load($environment);
    }

    public function testRejectsIssuerOutsideExactRealmPath(): void
    {
        $environment = $this->validEnvironment();
        $environment[KeycloakSsoEnvironment::ISSUER] = 'https://keyclock.gobaz.ir/other/realms/passbolt';

        $this->expectException(OidcConfigurationException::class);
        (new OidcConfigurationService())->load($environment);
    }

    public function testRejectsInvalidRedirectUri(): void
    {
        $environment = $this->validEnvironment();
        $environment[KeycloakSsoEnvironment::REDIRECT_URI] = 'https://evil.example/callback';

        $this->expectException(OidcConfigurationException::class);
        (new OidcConfigurationService())->load($environment);
    }

    public function testRejectsInvalidEncryptionKey(): void
    {
        $environment = $this->validEnvironment();
        $environment[KeycloakSsoEnvironment::TRANSACTION_ENCRYPTION_KEY] = base64_encode('too-short');

        $this->expectException(OidcConfigurationException::class);
        (new OidcConfigurationService())->load($environment);
    }

    public function testSecuritySecretRotationChangesConfigurationHash(): void
    {
        $service = new OidcConfigurationService();
        $environment = $this->validEnvironment();
        $initial = $service->load($environment)->configurationHash();

        $environment[KeycloakSsoEnvironment::CLIENT_SECRET] = 'rotated-client-secret';
        $clientSecretRotated = $service->load($environment)->configurationHash();
        $environment = $this->validEnvironment();
        $environment[KeycloakSsoEnvironment::TRANSACTION_ENCRYPTION_KEY] = base64_encode(str_repeat('r', 32));
        $transactionKeyRotated = $service->load($environment)->configurationHash();

        $this->assertNotSame($initial, $clientSecretRotated);
        $this->assertNotSame($initial, $transactionKeyRotated);
    }

    /** @return array<string, string> */
    private function validEnvironment(): array
    {
        return [
            KeycloakSsoEnvironment::ENABLED => 'true',
            KeycloakSsoEnvironment::ISSUER => 'https://keyclock.gobaz.ir/realms/passbolt',
            KeycloakSsoEnvironment::CLIENT_ID => 'passbolt',
            KeycloakSsoEnvironment::CLIENT_SECRET => 'client-secret',
            KeycloakSsoEnvironment::REDIRECT_URI => 'https://passbolt.gobaz.ir/auth/keycloak/callback',
            KeycloakSsoEnvironment::TRANSACTION_ENCRYPTION_KEY => base64_encode(str_repeat('k', 32)),
        ];
    }
}
