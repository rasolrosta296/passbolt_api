<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Configuration;

use Passbolt\KeycloakSso\Configuration\DeprovisioningConfigurationService;
use Passbolt\KeycloakSso\Configuration\KeycloakSsoEnvironment;
use Passbolt\KeycloakSso\Error\Exception\OidcConfigurationException;
use Passbolt\KeycloakSso\Model\Dto\DeprovisioningConfigurationDto;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class DeprovisioningConfigurationServiceTest extends TestCase
{
    public function testLoadsExplicitPolicyWithSafeDefaultGrace(): void
    {
        $configuration = (new DeprovisioningConfigurationService())->load($this->environment());

        $this->assertSame(DeprovisioningConfigurationDto::DEFAULT_GRACE_SECONDS, $configuration->graceSeconds);
        $this->assertSame('8d020e76-4951-58d2-b68e-99e2fc1053f8', $configuration->actorUserId);
        $this->assertFalse($configuration->reactivationEnabled);
        $this->assertFalse($configuration->automaticDeletionEnabled);
    }

    public function testLoadsExplicitAutomaticReactivationPolicy(): void
    {
        $environment = $this->environment();
        $environment[KeycloakSsoEnvironment::REACTIVATION_ENABLED] = 'true';

        $configuration = (new DeprovisioningConfigurationService())->load($environment);

        $this->assertTrue($configuration->reactivationEnabled);
    }

    public function testLoadsExplicitAutomaticDeletionPolicy(): void
    {
        $environment = $this->environment();
        $environment[KeycloakSsoEnvironment::AUTOMATIC_DELETION_ENABLED] = 'true';

        $configuration = (new DeprovisioningConfigurationService())->load($environment);

        $this->assertTrue($configuration->automaticDeletionEnabled);
    }

    #[DataProvider('invalidProvider')]
    public function testRejectsDisabledOrUnsafeGrace(array $changes): void
    {
        $this->expectException(OidcConfigurationException::class);
        (new DeprovisioningConfigurationService())->load(array_replace($this->environment(), $changes));
    }

    public static function invalidProvider(): array
    {
        return [
            'disabled' => [[KeycloakSsoEnvironment::DEPROVISIONING_ENABLED => 'false']],
            'ambiguous' => [[KeycloakSsoEnvironment::DEPROVISIONING_ENABLED => 'enabled']],
            'too short' => [[KeycloakSsoEnvironment::DEPROVISIONING_GRACE_SECONDS => '3599']],
            'too long' => [[KeycloakSsoEnvironment::DEPROVISIONING_GRACE_SECONDS => '2592001']],
            'not integer' => [[KeycloakSsoEnvironment::DEPROVISIONING_GRACE_SECONDS => 'one-week']],
            'ambiguous reactivation' => [[KeycloakSsoEnvironment::REACTIVATION_ENABLED => 'automatic']],
            'ambiguous automatic deletion' => [[
                KeycloakSsoEnvironment::AUTOMATIC_DELETION_ENABLED => 'automatic',
            ]],
        ];
    }

    /** @return array<string, string> */
    private function environment(): array
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
            KeycloakSsoEnvironment::DEPROVISIONING_ENABLED => 'true',
        ];
    }
}
