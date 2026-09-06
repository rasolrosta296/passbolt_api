<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Controller;

use App\Model\Entity\User;
use App\Test\Factory\UserFactory;
use Cake\ORM\TableRegistry;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction;
use Passbolt\KeycloakSso\Service\Oidc\OidcCookieService;
use Passbolt\KeycloakSso\Service\Transaction\ClaimOidcTransactionService;
use Passbolt\KeycloakSso\Service\Transaction\CreateOidcTransactionService;
use Passbolt\KeycloakSso\Service\Transaction\TransactionSecretProtector;
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

    public function testConfirmationPageDoesNotExtendIdentityLinkResultExpiry(): void
    {
        $user = UserFactory::make()->user()->active()->notDisabled()->persist();
        self::assertInstanceOf(User::class, $user);
        $configuration = new OidcConfigurationDto(
            'https://keyclock.gobaz.ir/realms/passbolt',
            'passbolt',
            'client-secret-for-tests',
            'https://passbolt.gobaz.ir/auth/keycloak/callback',
            random_bytes(32)
        );
        $protector = new TransactionSecretProtector($configuration->transactionEncryptionKey);
        $created = (new CreateOidcTransactionService($protector))->create(
            $configuration->issuer,
            $configuration->clientId,
            $configuration->redirectUri,
            $configuration->configurationHash(),
            OidcConfigurationDto::TRANSACTION_TTL_SECONDS,
            KeycloakSsoTransaction::PURPOSE_IDENTITY_LINK,
            $user->id
        );
        $transactions = new ClaimOidcTransactionService($protector);
        $transactions->claim($created->state, $created->browserBinding, $configuration->configurationHash());
        $token = $transactions->succeed(
            $created->id,
            OidcConfigurationDto::IDENTITY_LINK_RESULT_TTL_SECONDS
        );
        $table = TableRegistry::getTableLocator()->get('Passbolt/KeycloakSso.KeycloakSsoTransactions');
        $before = $table->get($created->id);
        self::assertInstanceOf(KeycloakSsoTransaction::class, $before);

        $this->logInAs($user);
        $this->cookie(OidcCookieService::LINK_RESULT_COOKIE, $token);
        $this->get('/auth/keycloak/link/confirm');

        $this->assertResponseOk();
        $after = $table->get($created->id);
        self::assertInstanceOf(KeycloakSsoTransaction::class, $after);
        $this->assertEquals($before->result_expires, $after->result_expires);
        $this->assertSame($before->result_token_hash, $after->result_token_hash);
        $this->assertSame(KeycloakSsoTransaction::STATUS_SUCCEEDED, $after->status);
    }
}
