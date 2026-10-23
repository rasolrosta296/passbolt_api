<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Configuration;

use Passbolt\KeycloakSso\Configuration\AccountRecoveryConfigurationService;
use Passbolt\KeycloakSso\Configuration\KeycloakSsoEnvironment;
use Passbolt\KeycloakSso\Error\Exception\OidcConfigurationException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class AccountRecoveryConfigurationServiceTest extends TestCase
{
    public function testLoadsOnlyExplicitlyEnabledIndependentPolicy(): void
    {
        $configuration = (new AccountRecoveryConfigurationService())->load([
            KeycloakSsoEnvironment::ACCOUNT_RECOVERY_ENABLED => 'true',
            KeycloakSsoEnvironment::ACCOUNT_RECOVERY_ACR => 'urn:keycloak:acr:mfa',
            KeycloakSsoEnvironment::ACCOUNT_RECOVERY_AMR => '["otp","pwd"]',
        ]);

        $this->assertSame('urn:keycloak:acr:mfa', $configuration->requiredAcr);
        $this->assertSame(['otp', 'pwd'], $configuration->requiredAmrValues);
    }

    #[DataProvider('invalidConfigurationProvider')]
    public function testFailsClosedForInvalidConfiguration(array $environment): void
    {
        $this->expectException(OidcConfigurationException::class);
        (new AccountRecoveryConfigurationService())->load($environment);
    }

    public static function invalidConfigurationProvider(): array
    {
        return [
            'disabled' => [[
                KeycloakSsoEnvironment::ACCOUNT_RECOVERY_ENABLED => 'false',
                KeycloakSsoEnvironment::ACCOUNT_RECOVERY_ACR => 'urn:keycloak:acr:mfa',
            ]],
            'ambiguous gate' => [[
                KeycloakSsoEnvironment::ACCOUNT_RECOVERY_ENABLED => 'enabled',
                KeycloakSsoEnvironment::ACCOUNT_RECOVERY_ACR => 'urn:keycloak:acr:mfa',
            ]],
            'missing acr' => [[KeycloakSsoEnvironment::ACCOUNT_RECOVERY_ENABLED => 'true']],
            'duplicate amr' => [[
                KeycloakSsoEnvironment::ACCOUNT_RECOVERY_ENABLED => 'true',
                KeycloakSsoEnvironment::ACCOUNT_RECOVERY_ACR => 'urn:keycloak:acr:mfa',
                KeycloakSsoEnvironment::ACCOUNT_RECOVERY_AMR => '["otp","otp"]',
            ]],
            'non-string amr' => [[
                KeycloakSsoEnvironment::ACCOUNT_RECOVERY_ENABLED => 'true',
                KeycloakSsoEnvironment::ACCOUNT_RECOVERY_ACR => 'urn:keycloak:acr:mfa',
                KeycloakSsoEnvironment::ACCOUNT_RECOVERY_AMR => '[1]',
            ]],
            'control character in amr' => [[
                KeycloakSsoEnvironment::ACCOUNT_RECOVERY_ENABLED => 'true',
                KeycloakSsoEnvironment::ACCOUNT_RECOVERY_ACR => 'urn:keycloak:acr:mfa',
                KeycloakSsoEnvironment::ACCOUNT_RECOVERY_AMR => '["otp\\u0000injected"]',
            ]],
        ];
    }
}
