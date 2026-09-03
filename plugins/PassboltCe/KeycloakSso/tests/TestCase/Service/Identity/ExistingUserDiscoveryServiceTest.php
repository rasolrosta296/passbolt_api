<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Service\Identity;

use App\Model\Entity\User;
use App\Test\Factory\UserFactory;
use Passbolt\KeycloakSso\Error\Exception\OidcValidationException;
use Passbolt\KeycloakSso\Service\Identity\ExistingUserDiscoveryService;
use Passbolt\KeycloakSso\Test\Lib\KeycloakSsoIntegrationTestCase;
use PHPUnit\Framework\Attributes\DataProvider;

final class ExistingUserDiscoveryServiceTest extends KeycloakSsoIntegrationTestCase
{
    public function testFindsExactlyOneActiveExistingUserByNormalizedEmail(): void
    {
        $user = UserFactory::make(['username' => 'User@Example.com'])->user()->active()->notDisabled()->persist();
        assert($user instanceof User);

        $match = (new ExistingUserDiscoveryService())->findExactlyOne('user@example.com');

        $this->assertSame($user->id, $match->id);
    }

    public function testRejectsUnknownUser(): void
    {
        $this->expectException(OidcValidationException::class);
        (new ExistingUserDiscoveryService())->findExactlyOne('unknown@example.com');
    }

    #[DataProvider('unusableUserProvider')]
    public function testRejectsUnusableUser(string $state): void
    {
        $factory = UserFactory::make(['username' => 'user@example.com'])->user()->active()->notDisabled();
        match ($state) {
            'disabled' => $factory->disabled(),
            'deleted' => $factory->deleted(),
            'inactive' => $factory->inactive(),
        };
        $factory->persist();

        $this->expectException(OidcValidationException::class);
        (new ExistingUserDiscoveryService())->findExactlyOne('user@example.com');
    }

    public static function unusableUserProvider(): array
    {
        return [
            'disabled' => ['disabled'],
            'deleted' => ['deleted'],
            'inactive' => ['inactive'],
        ];
    }

    public function testRejectsDuplicateNormalizedEmail(): void
    {
        UserFactory::make(['username' => 'user@example.com'])->user()->active()->notDisabled()->persist();
        UserFactory::make(['username' => 'USER@example.com'])->user()->active()->notDisabled()->persist();

        $this->expectException(OidcValidationException::class);
        (new ExistingUserDiscoveryService())->findExactlyOne('user@example.com');
    }
}
