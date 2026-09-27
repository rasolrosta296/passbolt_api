<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Configuration;

use Passbolt\KeycloakSso\Configuration\KeycloakSsoEnvironment;
use Passbolt\KeycloakSso\Configuration\ProvisioningConfigurationService;
use Passbolt\KeycloakSso\Error\Exception\OidcConfigurationException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ProvisioningConfigurationServiceTest extends TestCase
{
    public function testLoadsStrictIndependentProvisioningConfiguration(): void
    {
        $configuration = (new ProvisioningConfigurationService())->load($this->validEnvironment());

        $this->assertSame('https://keyclock.gobaz.ir/realms/passbolt', $configuration->issuer);
        $this->assertSame('https://keyclock.gobaz.ir/admin/realms/passbolt', $configuration->adminApiBaseUrl);
        $this->assertSame('passbolt-provisioning', $configuration->clientId);
        $this->assertSame('8d020e76-4951-58d2-b68e-99e2fc1053f8', $configuration->actorUserId);
        $this->assertSame(86_400, $configuration->initialLookbackSeconds);
        $this->assertSame(300, $configuration->overlapSeconds);
        $this->assertSame(100, $configuration->batchSize);
    }

    public function testPreservesNonDefaultIssuerPortForAdminApi(): void
    {
        $environment = $this->validEnvironment();
        $environment[KeycloakSsoEnvironment::ISSUER] = 'https://keyclock.gobaz.ir:8443/realms/passbolt';

        $configuration = (new ProvisioningConfigurationService())->load($environment);

        $this->assertSame(
            'https://keyclock.gobaz.ir:8443/admin/realms/passbolt',
            $configuration->adminApiBaseUrl
        );
    }

    #[DataProvider('invalidConfigurationProvider')]
    public function testRejectsInvalidConfiguration(array $changes): void
    {
        $this->expectException(OidcConfigurationException::class);

        (new ProvisioningConfigurationService())->load(array_replace($this->validEnvironment(), $changes));
    }

    public static function invalidConfigurationProvider(): array
    {
        return [
            'disabled' => [[KeycloakSsoEnvironment::PROVISIONING_ENABLED => 'false']],
            'ambiguous enabled' => [[KeycloakSsoEnvironment::PROVISIONING_ENABLED => 'yes-please']],
            'missing client id' => [[KeycloakSsoEnvironment::PROVISIONING_CLIENT_ID => false]],
            'missing secret' => [[KeycloakSsoEnvironment::PROVISIONING_CLIENT_SECRET => false]],
            'invalid actor UUID' => [[KeycloakSsoEnvironment::PROVISIONING_ACTOR_USER_ID => 'admin']],
            'lookback too small' => [[KeycloakSsoEnvironment::PROVISIONING_INITIAL_LOOKBACK_SECONDS => '59']],
            'lookback too large' => [[KeycloakSsoEnvironment::PROVISIONING_INITIAL_LOOKBACK_SECONDS => '604801']],
            'overlap non-integer' => [[KeycloakSsoEnvironment::PROVISIONING_OVERLAP_SECONDS => '5m']],
            'batch zero' => [[KeycloakSsoEnvironment::PROVISIONING_BATCH_SIZE => '0']],
            'batch too large' => [[KeycloakSsoEnvironment::PROVISIONING_BATCH_SIZE => '501']],
        ];
    }

    /** @return array<string, string> */
    private function validEnvironment(): array
    {
        return [
            KeycloakSsoEnvironment::ENABLED => 'true',
            KeycloakSsoEnvironment::ISSUER => 'https://keyclock.gobaz.ir/realms/passbolt',
            KeycloakSsoEnvironment::CLIENT_ID => 'passbolt',
            KeycloakSsoEnvironment::CLIENT_SECRET => 'oidc-secret',
            KeycloakSsoEnvironment::REDIRECT_URI => 'https://passbolt.gobaz.ir/auth/keycloak/callback',
            KeycloakSsoEnvironment::TRANSACTION_ENCRYPTION_KEY => base64_encode(str_repeat('k', 32)),
            KeycloakSsoEnvironment::PROVISIONING_ENABLED => 'true',
            KeycloakSsoEnvironment::PROVISIONING_CLIENT_ID => 'passbolt-provisioning',
            KeycloakSsoEnvironment::PROVISIONING_CLIENT_SECRET => 'provisioning-secret',
            KeycloakSsoEnvironment::PROVISIONING_ACTOR_USER_ID => '8d020e76-4951-58d2-b68e-99e2fc1053f8',
        ];
    }
}
