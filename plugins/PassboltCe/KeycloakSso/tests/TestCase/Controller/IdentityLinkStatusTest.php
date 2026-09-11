<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Controller;

use App\Model\Entity\User;
use App\Test\Factory\UserFactory;
use Passbolt\KeycloakSso\Configuration\KeycloakSsoEnvironment;
use Passbolt\KeycloakSso\Configuration\OidcConfigurationService;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;
use Passbolt\KeycloakSso\Model\Dto\PendingIdentityLink;
use Passbolt\KeycloakSso\Service\Identity\IdentityLinkPersistenceService;
use Passbolt\KeycloakSso\Test\Lib\KeycloakSsoIntegrationTestCase;

final class IdentityLinkStatusTest extends KeycloakSsoIntegrationTestCase
{
    /**
     * @var array<string, string|false>
     */
    private array $previousEnvironment = [];

    public function setUp(): void
    {
        parent::setUp();
        foreach ($this->environment() as $name => $value) {
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

    public function testStatusReportsConfiguredIssuerLinkWithoutIdentityData(): void
    {
        $user = $this->activeUser('status-linked@example.com');
        (new IdentityLinkPersistenceService())->create($user->id, new PendingIdentityLink(
            $this->configuration()->issuer,
            'opaque-subject',
            $user->username
        ));
        $this->logInAs($user);

        $this->getJson('/auth/keycloak/link/status.json');

        $this->assertSuccess();
        $this->assertTrue($this->_responseJsonBody->linked);
        $this->assertSame('no-store', $this->_response->getHeaderLine('Cache-Control'));
        $this->assertSame('no-cache', $this->_response->getHeaderLine('Pragma'));
        $this->assertResponseNotContains('opaque-subject');
        $this->assertResponseNotContains($user->username);
        $this->assertResponseNotContains($user->id);
    }

    public function testStatusReportsFalseForNoConfiguredIssuerLink(): void
    {
        $user = $this->activeUser('status-unlinked@example.com');
        $this->logInAs($user);

        $this->getJson('/auth/keycloak/link/status.json');

        $this->assertSuccess();
        $this->assertFalse($this->_responseJsonBody->linked);
    }

    public function testStatusRequiresJsonAndAuthenticatedActiveUser(): void
    {
        $this->getJson('/auth/keycloak/link/status.json');
        $this->assertResponseCode(401);

        $user = $this->activeUser('status-html@example.com');
        $this->logInAs($user);
        $this->get('/auth/keycloak/link/status');
        $this->assertResponseCode(404);
    }

    private function activeUser(string $email): User
    {
        $user = UserFactory::make(['username' => $email])->user()->active()->notDisabled()->persist();
        self::assertInstanceOf(User::class, $user);

        return $user;
    }

    private function configuration(): OidcConfigurationDto
    {
        return (new OidcConfigurationService())->load();
    }

    /** @return array<string, string> */
    private function environment(): array
    {
        return [
            KeycloakSsoEnvironment::ENABLED => 'true',
            KeycloakSsoEnvironment::ISSUER => 'https://identity.example.test/realms/passbolt',
            KeycloakSsoEnvironment::CLIENT_ID => 'passbolt-test',
            KeycloakSsoEnvironment::CLIENT_SECRET => 'unit-test-client-secret',
            KeycloakSsoEnvironment::REDIRECT_URI => 'https://passbolt.example.test/auth/keycloak/callback',
            KeycloakSsoEnvironment::TRANSACTION_ENCRYPTION_KEY => base64_encode(str_repeat('t', 32)),
        ];
    }
}
