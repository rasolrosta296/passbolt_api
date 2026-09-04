<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Controller;

use App\Model\Entity\User;
use App\Test\Factory\UserFactory;
use Passbolt\KeycloakSso\Configuration\KeycloakSsoEnvironment;
use Passbolt\KeycloakSso\Test\Lib\KeycloakSsoIntegrationTestCase;

final class CryptoEnrollmentRevocationControllerTest extends KeycloakSsoIntegrationTestCase
{
    /** @var array<string, string|false> */
    private array $previousEnvironment = [];

    public function setUp(): void
    {
        parent::setUp();
        $configuration = [
            KeycloakSsoEnvironment::ISSUER => 'https://keyclock.gobaz.ir/realms/passbolt',
            KeycloakSsoEnvironment::CLIENT_ID => 'passbolt',
            KeycloakSsoEnvironment::CLIENT_SECRET => 'test-client-secret',
            KeycloakSsoEnvironment::REDIRECT_URI => 'https://passbolt.gobaz.ir/auth/keycloak/callback',
            KeycloakSsoEnvironment::TRANSACTION_ENCRYPTION_KEY => base64_encode(str_repeat('T', 32)),
        ];
        foreach ($configuration as $name => $value) {
            $this->previousEnvironment[$name] = getenv($name);
            putenv($name . '=' . $value);
        }
    }

    public function tearDown(): void
    {
        foreach ($this->previousEnvironment as $name => $value) {
            putenv($value === false ? $name : $name . '=' . $value);
        }
        parent::tearDown();
    }

    public function testAuthenticatedUserCanIdempotentlyRevokeWhenNoEnrollmentExists(): void
    {
        $user = UserFactory::make()->user()->active()->notDisabled()->persist();
        self::assertInstanceOf(User::class, $user);
        $this->logInAs($user);

        $this->postJson('/auth/keycloak/crypto/enrollments/revoke.json');

        $this->assertResponseOk();
        $this->assertSame([], (array)$this->_responseJsonBody->client_enrollment_uuids);
        $this->assertSame('no-store', $this->_response->getHeaderLine('Cache-Control'));
        $this->assertSame('no-cache', $this->_response->getHeaderLine('Pragma'));
    }

    public function testRevocationRequiresAuthenticatedPassboltSession(): void
    {
        $this->postJson('/auth/keycloak/crypto/enrollments/revoke.json');

        $this->assertResponseCode(302);
    }

    public function testRevocationRequiresCsrfEvenWithAuthenticatedSession(): void
    {
        $user = UserFactory::make()->user()->active()->notDisabled()->persist();
        self::assertInstanceOf(User::class, $user);
        $this->logInAs($user);
        $this->disableCsrfToken();

        $this->postJson('/auth/keycloak/crypto/enrollments/revoke.json');

        $this->assertResponseCode(403);
    }
}
