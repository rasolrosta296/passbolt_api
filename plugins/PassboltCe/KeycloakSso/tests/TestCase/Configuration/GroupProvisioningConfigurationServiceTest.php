<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Configuration;

use Passbolt\KeycloakSso\Configuration\GroupProvisioningConfigurationService;
use Passbolt\KeycloakSso\Configuration\KeycloakSsoEnvironment;
use Passbolt\KeycloakSso\Error\Exception\OidcConfigurationException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class GroupProvisioningConfigurationServiceTest extends TestCase
{
    public function testRequiresExplicitTrue(): void
    {
        $service = new GroupProvisioningConfigurationService();
        $service->assertEnabled([
            KeycloakSsoEnvironment::GROUP_PROVISIONING_ENABLED => 'true',
        ]);

        $this->assertTrue($service->isEnabled([
            KeycloakSsoEnvironment::GROUP_PROVISIONING_ENABLED => 'true',
        ]));
    }

    #[DataProvider('disabledProvider')]
    public function testRejectsDisabledOrAmbiguousValues(string|false $value): void
    {
        $this->expectException(OidcConfigurationException::class);
        (new GroupProvisioningConfigurationService())->assertEnabled([
            KeycloakSsoEnvironment::GROUP_PROVISIONING_ENABLED => $value,
        ]);
    }

    public static function disabledProvider(): array
    {
        return [
            'missing' => [false],
            'false' => ['false'],
            'ambiguous' => ['enabled'],
        ];
    }
}
