<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Service\Identity;

use App\Model\Entity\User;
use App\Test\Factory\UserFactory;
use App\Utility\UuidFactory;
use Cake\Database\Exception\QueryException;
use Cake\I18n\DateTime;
use Cake\ORM\Table;
use Cake\ORM\TableRegistry;
use Passbolt\KeycloakSso\Error\Exception\IdentityLinkException;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;
use Passbolt\KeycloakSso\Model\Dto\ValidatedOidcIdentity;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoIdentity;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction;
use Passbolt\KeycloakSso\Service\Audit\IdentityLinkAuditService;
use Passbolt\KeycloakSso\Service\Identity\ConfirmIdentityLinkService;
use Passbolt\KeycloakSso\Service\Identity\ExistingUserDiscoveryService;
use Passbolt\KeycloakSso\Service\Identity\IdentityLinkPersistenceService;
use Passbolt\KeycloakSso\Service\Identity\IdentityLinkProofProtector;
use Passbolt\KeycloakSso\Service\Identity\PrepareIdentityLinkService;
use Passbolt\KeycloakSso\Service\Identity\UnlinkIdentityService;
use Passbolt\KeycloakSso\Service\Transaction\ClaimOidcTransactionService;
use Passbolt\KeycloakSso\Service\Transaction\CreateOidcTransactionService;
use Passbolt\KeycloakSso\Service\Transaction\TransactionSecretProtector;
use Passbolt\KeycloakSso\Test\Lib\KeycloakSsoIntegrationTestCase;
use Throwable;

final class IdentityLinkServicesTest extends KeycloakSsoIntegrationTestCase
{
    private OidcConfigurationDto $configuration;
    private TransactionSecretProtector $transactionProtector;

    public function setUp(): void
    {
        parent::setUp();
        $this->configuration = new OidcConfigurationDto(
            'https://keyclock.gobaz.ir/realms/passbolt',
            'passbolt',
            'client-secret-for-tests',
            'https://passbolt.gobaz.ir/auth/keycloak/callback',
            random_bytes(32)
        );
        $this->transactionProtector = new TransactionSecretProtector(
            $this->configuration->transactionEncryptionKey
        );
    }

    public function testFreshProofCanBeConfirmedOnceAndUnlinked(): void
    {
        $user = $this->activeUser('user@example.com');
        $token = $this->prepareResult($user, 'immutable-subject', 'user@example.com');

        $linked = $this->confirmer()->confirm($token, $user->id);

        $this->assertInstanceOf(KeycloakSsoIdentity::class, $linked);
        $this->assertSame($user->id, $linked->user_id);
        $this->assertSame($this->configuration->issuer, $linked->issuer);
        $this->assertSame('immutable-subject', $linked->subject);
        $this->assertSame('user@example.com', $linked->email_at_link_time);

        $this->expectException(IdentityLinkException::class);
        try {
            $this->confirmer()->confirm($token, $user->id);
        } finally {
            (new UnlinkIdentityService($this->configuration->issuer, new IdentityLinkAuditService()))
                ->unlink($user->id);
            $this->assertSame(0, $this->identities()->find()->count());
        }
    }

    public function testEmailCandidateMustBeSameAuthenticatedUser(): void
    {
        $authenticatedUser = $this->activeUser('authenticated@example.com');
        $otherUser = $this->activeUser('other@example.com');

        $this->expectException(IdentityLinkException::class);
        $this->expectExceptionMessage('could not be completed');
        $this->prepareResult($authenticatedUser, 'immutable-subject', $otherUser->username);
    }

    public function testDuplicateNormalizedEmailFailsClosed(): void
    {
        $user = $this->activeUser('user@example.com');
        $this->activeUser('USER@example.com');

        $this->expectException(Throwable::class);
        $this->prepareResult($user, 'immutable-subject', 'user@example.com');
    }

    public function testDisabledUserCannotConfirm(): void
    {
        $user = $this->activeUser('user@example.com');
        $token = $this->prepareResult($user, 'immutable-subject', 'user@example.com');
        $users = TableRegistry::getTableLocator()->get('Users');
        $users->updateAll(['disabled' => DateTime::now()], ['id' => $user->id]);

        try {
            $this->confirmer()->confirm($token, $user->id);
            $this->fail('A disabled user must not be linked.');
        } catch (Throwable) {
            $this->assertSame(0, $this->identities()->find()->count());
        }
    }

    public function testDeletedUserCannotConfirm(): void
    {
        $user = $this->activeUser('user@example.com');
        $token = $this->prepareResult($user, 'immutable-subject', 'user@example.com');
        TableRegistry::getTableLocator()->get('Users')->updateAll(['deleted' => true], ['id' => $user->id]);

        try {
            $this->confirmer()->confirm($token, $user->id);
            $this->fail('A deleted user must not be linked.');
        } catch (Throwable) {
            $this->assertSame(0, $this->identities()->find()->count());
        }
    }

    public function testProviderIdentityAndProviderUserCollisionsFailClosed(): void
    {
        $first = $this->activeUser('first@example.com');
        $second = $this->activeUser('second@example.com');
        $firstToken = $this->prepareResult($first, 'same-subject', $first->username);
        $this->confirmer()->confirm($firstToken, $first->id);

        try {
            $this->prepareResult($second, 'same-subject', $second->username);
            $this->fail('The same issuer/subject must not be linked to another user.');
        } catch (IdentityLinkException $exception) {
            $this->assertSame('provider_identity_collision', $exception->reasonCode());
        }

        try {
            $this->prepareResult($first, 'different-subject', $first->username);
            $this->fail('The same issuer/user slot must not accept another subject.');
        } catch (IdentityLinkException $exception) {
            $this->assertSame('provider_user_collision', $exception->reasonCode());
        }
    }

    public function testTwoPreparedConcurrentRequestsAreSerializedByDatabaseUniqueness(): void
    {
        $user = $this->activeUser('user@example.com');
        $firstToken = $this->prepareResult($user, 'immutable-subject', $user->username);
        $secondToken = $this->prepareResult($user, 'immutable-subject', $user->username);

        $this->confirmer()->confirm($firstToken, $user->id);

        try {
            $this->confirmer()->confirm($secondToken, $user->id);
            $this->fail('Only one concurrent identity-link confirmation may succeed.');
        } catch (IdentityLinkException $exception) {
            $this->assertContains($exception->reasonCode(), [
                'identity_already_linked',
                'database_identity_collision',
            ]);
            $this->assertSame(1, $this->identities()->find()->count());
        }
    }

    public function testExpiredIdentityProofCannotBeConfirmed(): void
    {
        $user = $this->activeUser('user@example.com');
        $token = $this->prepareResult($user, 'immutable-subject', $user->username);
        TableRegistry::getTableLocator()->get('Passbolt/KeycloakSso.KeycloakSsoTransactions')->updateAll(
            ['result_expires' => DateTime::yesterday()],
            ['result_token_hash' => CreateOidcTransactionService::hash($token)]
        );

        $this->expectException(IdentityLinkException::class);
        $this->confirmer()->confirm($token, $user->id);
    }

    public function testMilestoneOneIdentityProofResultCannotBeReusedForLinking(): void
    {
        $user = $this->activeUser('user@example.com');
        $created = (new CreateOidcTransactionService($this->transactionProtector))->create(
            $this->configuration->issuer,
            $this->configuration->clientId,
            $this->configuration->redirectUri,
            $this->configuration->configurationHash(),
            OidcConfigurationDto::TRANSACTION_TTL_SECONDS
        );
        $transactions = new ClaimOidcTransactionService($this->transactionProtector);
        $claimed = $transactions->claim(
            $created->state,
            $created->browserBinding,
            $this->configuration->configurationHash()
        );
        $token = $transactions->succeed(
            $claimed['transaction']->id,
            OidcConfigurationDto::RESULT_TTL_SECONDS
        );

        $this->expectException(IdentityLinkException::class);
        $this->confirmer()->confirm($token, $user->id);
    }

    public function testChangedEmailDoesNotMoveExistingMapping(): void
    {
        $user = $this->activeUser('before@example.com');
        $token = $this->prepareResult($user, 'immutable-subject', $user->username);
        $linked = $this->confirmer()->confirm($token, $user->id);
        TableRegistry::getTableLocator()->get('Users')->updateAll(
            ['username' => 'after@example.com'],
            ['id' => $user->id]
        );

        $reloaded = $this->identities()->get($linked->id);
        self::assertInstanceOf(KeycloakSsoIdentity::class, $reloaded);
        $this->assertSame($user->id, $reloaded->user_id);
        $this->assertSame('before@example.com', $reloaded->email_at_link_time);
    }

    public function testIssuerAndSubjectAreOpaqueCaseSensitiveNamespaces(): void
    {
        $user = $this->activeUser('user@example.com');
        $token = $this->prepareResult($user, 'Subject-A', $user->username);
        $this->confirmer()->confirm($token, $user->id);

        $this->assertSame(1, $this->identities()->find()->where([
            'issuer' => $this->configuration->issuer,
            'subject' => 'Subject-A',
        ])->count());
        $this->assertSame(0, $this->identities()->find()->where([
            'issuer' => strtoupper($this->configuration->issuer),
            'subject' => 'subject-a',
        ])->count());
    }

    public function testDatabaseUniquenessIsFinalConcurrentRequestBarrier(): void
    {
        $first = $this->activeUser('first@example.com');
        $second = $this->activeUser('second@example.com');
        $connection = $this->identities()->getConnection();
        $base = [
            'issuer' => $this->configuration->issuer,
            'subject' => 'same-subject',
            'email_at_link_time' => 'first@example.com',
            'created' => DateTime::now()->format('Y-m-d H:i:s'),
            'modified' => DateTime::now()->format('Y-m-d H:i:s'),
            'last_seen' => DateTime::now()->format('Y-m-d H:i:s'),
        ];
        $connection->insert('keycloak_sso_identities', ['id' => $this->uuid(), 'user_id' => $first->id] + $base);

        $this->expectException(QueryException::class);
        $connection->insert('keycloak_sso_identities', [
            'id' => $this->uuid(),
            'user_id' => $second->id,
        ] + $base);
    }

    public function testForeignKeyCascadeRemovesIdentityWhenUserIsHardDeleted(): void
    {
        $user = $this->activeUser('user@example.com');
        $token = $this->prepareResult($user, 'immutable-subject', $user->username);
        $this->confirmer()->confirm($token, $user->id);

        TableRegistry::getTableLocator()->get('Users')->deleteOrFail($user);

        $this->assertSame(0, $this->identities()->find()->count());
    }

    private function prepareResult(User $user, string $subject, string $email): string
    {
        $created = (new CreateOidcTransactionService($this->transactionProtector))->create(
            $this->configuration->issuer,
            $this->configuration->clientId,
            $this->configuration->redirectUri,
            $this->configuration->configurationHash(),
            OidcConfigurationDto::TRANSACTION_TTL_SECONDS,
            KeycloakSsoTransaction::PURPOSE_IDENTITY_LINK,
            $user->id
        );
        $transactions = new ClaimOidcTransactionService($this->transactionProtector);
        $claimed = $transactions->claim(
            $created->state,
            $created->browserBinding,
            $this->configuration->configurationHash()
        );
        (new PrepareIdentityLinkService(
            new ExistingUserDiscoveryService(),
            new IdentityLinkPersistenceService(),
            new IdentityLinkProofProtector($this->transactionProtector)
        ))->prepare($claimed['transaction'], new ValidatedOidcIdentity($subject, $email));

        return $transactions->succeed(
            $claimed['transaction']->id,
            OidcConfigurationDto::RESULT_TTL_SECONDS
        );
    }

    private function confirmer(): ConfirmIdentityLinkService
    {
        return new ConfirmIdentityLinkService(
            $this->configuration->issuer,
            $this->configuration->configurationHash(),
            new ExistingUserDiscoveryService(),
            new IdentityLinkPersistenceService(),
            new IdentityLinkProofProtector($this->transactionProtector),
            new IdentityLinkAuditService()
        );
    }

    private function activeUser(string $email): User
    {
        $user = UserFactory::make(['username' => $email])->user()->active()->notDisabled()->persist();
        self::assertInstanceOf(User::class, $user);

        return $user;
    }

    private function identities(): Table
    {
        return TableRegistry::getTableLocator()->get('Passbolt/KeycloakSso.KeycloakSsoIdentities');
    }

    private function uuid(): string
    {
        return UuidFactory::uuid();
    }
}
