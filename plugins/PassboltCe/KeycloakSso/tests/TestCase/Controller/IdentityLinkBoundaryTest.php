<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Controller;

use App\Model\Entity\User;
use App\Test\Factory\UserFactory;
use Cake\ORM\TableRegistry;
use Passbolt\KeycloakSso\Service\Oidc\OidcCookieService;
use Passbolt\KeycloakSso\Test\Lib\KeycloakSsoIntegrationTestCase;

final class IdentityLinkBoundaryTest extends KeycloakSsoIntegrationTestCase
{
    public function testUnauthenticatedUserCannotStartOrViewLinking(): void
    {
        $this->get('/auth/keycloak/link');
        $this->assertResponseCode(302);

        $this->post('/auth/keycloak/link/start');
        $this->assertResponseCode(302);
    }

    public function testAuthenticatedServerSessionCanViewExplicitLinkForm(): void
    {
        $user = UserFactory::make()->user()->active()->notDisabled()->persist();
        self::assertInstanceOf(User::class, $user);
        $this->logInAs($user);

        $this->get('/auth/keycloak/link');

        $this->assertResponseOk();
        $this->assertResponseContains('Link Keycloak identity');
        $this->assertResponseContains('_csrfToken');
    }

    public function testUnlinkRequiresCsrfEvenWithAuthenticatedSession(): void
    {
        $user = UserFactory::make()->user()->active()->notDisabled()->persist();
        self::assertInstanceOf(User::class, $user);
        $this->logInAs($user);
        $this->disableCsrfToken();

        $this->post('/auth/keycloak/unlink', ['confirmation' => 'unlink_keycloak_identity']);

        $this->assertResponseCode(403);
    }

    public function testUnlinkRequiresAuthenticatedPassboltSession(): void
    {
        $this->post('/auth/keycloak/unlink', ['confirmation' => 'unlink_keycloak_identity']);

        $this->assertResponseCode(302);
    }

    public function testOidcOnlyResultCannotConfirmLinkWithoutPassboltSession(): void
    {
        $this->configRequest(['cookies' => [
            OidcCookieService::LINK_RESULT_COOKIE => str_repeat('r', 43),
        ]]);

        $this->get('/auth/keycloak/link/confirm');

        $this->assertResponseCode(302);
        $this->assertSame(
            0,
            TableRegistry::getTableLocator()
                ->get('Passbolt/KeycloakSso.KeycloakSsoIdentities')
                ->find()
                ->count()
        );
    }
}
