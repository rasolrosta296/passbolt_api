<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Controller;

use App\Test\Factory\UserFactory;
use Passbolt\KeycloakSso\Test\Lib\KeycloakSsoIntegrationTestCase;
use PHPUnit\Framework\Attributes\DataProvider;

final class CryptoSsoJsonRequestTest extends KeycloakSsoIntegrationTestCase
{
    #[DataProvider('unauthenticatedJsonEndpointProvider')]
    public function testUnauthenticatedCryptoApiRejectsNonJsonBeforeMutation(string $route): void
    {
        $this->post($route, []);

        $this->assertResponseCode(404);
        $this->assertCryptoStateIsEmpty();
    }

    #[DataProvider('authenticatedJsonEndpointProvider')]
    public function testAuthenticatedCryptoApiRejectsNonJsonBeforeMutation(string $route): void
    {
        $user = UserFactory::make()->user()->active()->notDisabled()->persist();
        $this->logInAs($user);

        $this->post($route, []);

        $this->assertResponseCode(404);
        $this->assertCryptoStateIsEmpty();
    }

    /** @return array<string, array{string}> */
    public static function unauthenticatedJsonEndpointProvider(): array
    {
        return [
            'login start' => ['/auth/keycloak/crypto/login/start'],
            'share release' => ['/auth/keycloak/crypto/release'],
        ];
    }

    /** @return array<string, array{string}> */
    public static function authenticatedJsonEndpointProvider(): array
    {
        return [
            'enrollment start' => ['/auth/keycloak/crypto/enroll/start'],
            'enrollment completion' => ['/auth/keycloak/crypto/enroll'],
            'rotation start' => ['/auth/keycloak/crypto/rotation/start'],
            'rotation completion' => ['/auth/keycloak/crypto/rotation/complete'],
            'rotation failure' => ['/auth/keycloak/crypto/rotation/fail'],
        ];
    }

    private function assertCryptoStateIsEmpty(): void
    {
        $this->assertSame(0, $this->getTableLocator()
            ->get('Passbolt/KeycloakSso.KeycloakSsoTransactions')->find()->count());
        $this->assertSame(0, $this->getTableLocator()
            ->get('Passbolt/KeycloakSso.KeycloakSsoCryptoRequests')->find()->count());
        $this->assertSame(0, $this->getTableLocator()
            ->get('Passbolt/KeycloakSso.KeycloakSsoCryptoEnrollments')->find()->count());
        $this->assertSame(0, $this->getTableLocator()
            ->get('Passbolt/KeycloakSso.KeycloakSsoRotationBarriers')->find()->count());
    }
}
