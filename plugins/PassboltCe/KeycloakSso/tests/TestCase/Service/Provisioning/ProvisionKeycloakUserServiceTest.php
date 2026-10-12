<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Service\Provisioning;

use App\Model\Entity\AuthenticationToken;
use App\Model\Entity\User;
use App\Model\Table\UsersTable;
use App\Notification\Email\Redactor\CoreEmailRedactorPool;
use App\Notification\NotificationSettings\CoreNotificationSettingsDefinition;
use App\Test\Factory\AuthenticationTokenFactory;
use App\Test\Factory\RoleFactory;
use App\Test\Factory\UserFactory;
use App\Test\Lib\Model\EmailQueueTrait;
use App\Utility\UuidFactory;
use Cake\Event\EventManager;
use Cake\ORM\TableRegistry;
use Passbolt\EmailDigest\Test\Factory\EmailQueueFactory;
use Passbolt\KeycloakSso\Error\Exception\OidcHttpStatusException;
use Passbolt\KeycloakSso\Model\Dto\KeycloakAdminEventDto;
use Passbolt\KeycloakSso\Model\Dto\OidcDiscoveryDocument;
use Passbolt\KeycloakSso\Model\Dto\ProvisioningConfigurationDto;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoProvisionedUser;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoProvisioningEvent;
use Passbolt\KeycloakSso\Service\Audit\ProvisioningAuditService;
use Passbolt\KeycloakSso\Service\Provisioning\KeycloakProvisioningApiService;
use Passbolt\KeycloakSso\Service\Provisioning\ProvisionKeycloakUserService;
use Passbolt\KeycloakSso\Test\Lib\KeycloakSsoIntegrationTestCase;
use Passbolt\KeycloakSso\Test\Utility\QueuedOidcHttpClient;

final class ProvisionKeycloakUserServiceTest extends KeycloakSsoIntegrationTestCase
{
    use EmailQueueTrait;

    public function testCreatesOnlyInactiveUserInvitationAndProvisioningProvenance(): void
    {
        EventManager::instance()
            ->on(new CoreEmailRedactorPool())
            ->on(new CoreNotificationSettingsDefinition());
        $this->initEmailForServiceTest();
        RoleFactory::make()->user()->persist();
        $actor = UserFactory::make()->admin()->active()->notDisabled()->persist();
        $this->assertInstanceOf(User::class, $actor);
        $service = $this->service($actor->id, $this->eligibleUserResponses());

        $outcome = $service->process($this->event());

        $this->assertSame(ProvisionKeycloakUserService::OUTCOME_PROVISIONED, $outcome);
        $users = TableRegistry::getTableLocator()->get('Users');
        $created = $users->find()->where(['username' => 'new.user@example.test'])->firstOrFail();
        $this->assertInstanceOf(UsersTable::class, $users);
        $this->assertInstanceOf(User::class, $created);
        $this->assertFalse($created->active);
        $this->assertFalse($created->deleted);
        $this->assertNull($created->disabled);
        $this->assertSame(1, AuthenticationTokenFactory::find()->where([
            'user_id' => $created->id,
            'type' => AuthenticationToken::TYPE_REGISTER,
        ])->count());
        $this->assertSame(1, AuthenticationTokenFactory::find()->where(['user_id' => $created->id])->count());
        $this->assertSame(1, EmailQueueFactory::count());
        $this->assertSame(0, AuthenticationTokenFactory::find()->where([
            'user_id' => $created->id,
            'type IN' => [AuthenticationToken::TYPE_LOGIN, AuthenticationToken::TYPE_REFRESH_TOKEN],
        ])->count());
        $this->assertSame($users->Roles->getIdByName('user'), $created->role_id);
        $this->assertSame(0, TableRegistry::getTableLocator()->get('Gpgkeys')->find()->where([
            'user_id' => $created->id,
        ])->count());
        $this->assertSame(1, TableRegistry::getTableLocator()
            ->get('Passbolt/KeycloakSso.KeycloakSsoProvisionedUsers')->find()->where([
                'issuer' => 'https://keyclock.gobaz.ir/realms/passbolt',
                'subject' => $this->event()->subject,
                'user_id' => $created->id,
            ])->count());
        $this->assertSame(0, TableRegistry::getTableLocator()
            ->get('Passbolt/KeycloakSso.KeycloakSsoIdentities')->find()->count());
        $this->assertSame(KeycloakSsoProvisioningEvent::STATUS_PROVISIONED, $this->savedEventStatus());
    }

    public function testUnverifiedEmailIsSkippedWithoutCreatingUser(): void
    {
        RoleFactory::make()->user()->persist();
        $actor = UserFactory::make()->admin()->active()->notDisabled()->persist();
        $this->assertInstanceOf(User::class, $actor);
        $responses = $this->eligibleUserResponses();
        $responses[1]['emailVerified'] = false;

        $outcome = $this->service($actor->id, $responses)->process($this->event());

        $this->assertSame(ProvisionKeycloakUserService::OUTCOME_SKIPPED, $outcome);
        $this->assertSame(0, TableRegistry::getTableLocator()->get('Users')->find()->where([
            'username' => 'new.user@example.test',
        ])->count());
        $this->assertSame(KeycloakSsoProvisioningEvent::STATUS_SKIPPED, $this->savedEventStatus());
    }

    public function testDeletedKeycloakUserIsTerminallySkippedWithoutCreatingUser(): void
    {
        RoleFactory::make()->user()->persist();
        $actor = UserFactory::make()->admin()->active()->notDisabled()->persist();
        $this->assertInstanceOf(User::class, $actor);

        $outcome = $this->service($actor->id, [
            ['access_token' => 'service-token', 'token_type' => 'Bearer'],
            new OidcHttpStatusException(404),
        ])->process($this->event());

        $this->assertSame(ProvisionKeycloakUserService::OUTCOME_SKIPPED, $outcome);
        $this->assertSame(KeycloakSsoProvisioningEvent::STATUS_SKIPPED, $this->savedEventStatus());
        $this->assertSame('user_absent', $this->savedEventFailureCode());
        $this->assertSame(0, TableRegistry::getTableLocator()->get('Users')->find()->where([
            'username' => 'new.user@example.test',
        ])->count());
    }

    public function testDeletedKeycloakUserDryRunIsSkippedWithoutPersistingCheckpoint(): void
    {
        RoleFactory::make()->user()->persist();
        $actor = UserFactory::make()->admin()->active()->notDisabled()->persist();
        $this->assertInstanceOf(User::class, $actor);

        $outcome = $this->service($actor->id, [
            ['access_token' => 'service-token', 'token_type' => 'Bearer'],
            new OidcHttpStatusException(404),
        ])->process($this->event(), true);

        $this->assertSame(ProvisionKeycloakUserService::OUTCOME_SKIPPED, $outcome);
        $this->assertSame(0, TableRegistry::getTableLocator()
            ->get('Passbolt/KeycloakSso.KeycloakSsoProvisioningEvents')->find()->count());
    }

    public function testKeycloakUserLookupFailureRemainsRetryableFailure(): void
    {
        RoleFactory::make()->user()->persist();
        $actor = UserFactory::make()->admin()->active()->notDisabled()->persist();
        $this->assertInstanceOf(User::class, $actor);

        $outcome = $this->service($actor->id, [
            ['access_token' => 'service-token', 'token_type' => 'Bearer'],
            new OidcHttpStatusException(503),
        ])->process($this->event());

        $this->assertSame(ProvisionKeycloakUserService::OUTCOME_FAILED, $outcome);
        $this->assertSame(KeycloakSsoProvisioningEvent::STATUS_FAILED, $this->savedEventStatus());
        $this->assertSame('keycloak_unavailable', $this->savedEventFailureCode());
    }

    public function testNewSubjectCanProvisionReplacementAfterOldPassboltUserWasSoftDeleted(): void
    {
        EventManager::instance()
            ->on(new CoreEmailRedactorPool())
            ->on(new CoreNotificationSettingsDefinition());
        $this->initEmailForServiceTest();
        RoleFactory::make()->user()->persist();
        $actor = UserFactory::make()->admin()->active()->notDisabled()->persist();
        $this->assertInstanceOf(User::class, $actor);
        $deleted = UserFactory::make(['username' => 'new.user@example.test'])->user()->deleted()->persist();
        $this->assertInstanceOf(User::class, $deleted);
        $provisioned = TableRegistry::getTableLocator()->get(
            'Passbolt/KeycloakSso.KeycloakSsoProvisionedUsers'
        );
        $oldProvenance = $provisioned->newEntity([
            'id' => UuidFactory::uuid(),
            'user_id' => $deleted->id,
            'issuer' => 'https://keyclock.gobaz.ir/realms/passbolt',
            'subject' => 'old-keycloak-subject',
            'email_at_provisioning' => 'new.user@example.test',
            'source_event_id' => '53a9a0c1-8ce8-4cbc-9b38-04938fea2311',
            'lifecycle_status' => KeycloakSsoProvisionedUser::STATUS_DELETED,
        ], ['accessibleFields' => ['*' => true]]);
        $provisioned->saveOrFail($oldProvenance);

        $outcome = $this->service($actor->id, $this->eligibleUserResponses())->process($this->event());

        $this->assertSame(ProvisionKeycloakUserService::OUTCOME_PROVISIONED, $outcome);
        $this->assertSame(KeycloakSsoProvisioningEvent::STATUS_PROVISIONED, $this->savedEventStatus());
        $users = TableRegistry::getTableLocator()->get('Users');
        $this->assertSame(2, $users->find()->where([
            'LOWER(Users.username)' => 'new.user@example.test',
        ])->count());
        $replacement = $users->find()->where([
            'LOWER(Users.username)' => 'new.user@example.test',
            'Users.deleted' => false,
        ])->firstOrFail();
        $this->assertInstanceOf(User::class, $replacement);
        $this->assertFalse($replacement->active);
        $this->assertNotSame($deleted->id, $replacement->id);
        $this->assertSame(1, $users->find()->where([
            'Users.id' => $deleted->id,
            'Users.deleted' => true,
        ])->count());
        $this->assertSame(1, AuthenticationTokenFactory::find()->where([
            'user_id' => $replacement->id,
            'type' => AuthenticationToken::TYPE_REGISTER,
        ])->count());
        $this->assertSame(0, TableRegistry::getTableLocator()
            ->get('Passbolt/KeycloakSso.KeycloakSsoIdentities')->find()->count());
        $this->assertSame(0, TableRegistry::getTableLocator()->get('Gpgkeys')->find()->where([
            'user_id' => $replacement->id,
        ])->count());
        $this->assertSame(2, $provisioned->find()->where([
            'issuer' => 'https://keyclock.gobaz.ir/realms/passbolt',
        ])->count());
        $this->assertSame(1, $provisioned->find()->where([
            'subject' => 'old-keycloak-subject',
            'user_id' => $deleted->id,
        ])->count());
        $this->assertSame(1, $provisioned->find()->where([
            'subject' => $this->event()->subject,
            'user_id' => $replacement->id,
        ])->count());
        $this->assertSame(1, EmailQueueFactory::count());
    }

    public function testSameProvisionedSubjectRemainsCollisionAfterOldPassboltUserWasSoftDeleted(): void
    {
        RoleFactory::make()->user()->persist();
        $actor = UserFactory::make()->admin()->active()->notDisabled()->persist();
        $deleted = UserFactory::make(['username' => 'new.user@example.test'])->user()->deleted()->persist();
        $this->assertInstanceOf(User::class, $actor);
        $this->assertInstanceOf(User::class, $deleted);
        $table = TableRegistry::getTableLocator()->get(
            'Passbolt/KeycloakSso.KeycloakSsoProvisionedUsers'
        );
        $provenance = $table->newEntity([
            'id' => UuidFactory::uuid(),
            'user_id' => $deleted->id,
            'issuer' => 'https://keyclock.gobaz.ir/realms/passbolt',
            'subject' => $this->event()->subject,
            'email_at_provisioning' => 'new.user@example.test',
            'source_event_id' => '53a9a0c1-8ce8-4cbc-9b38-04938fea2311',
            'lifecycle_status' => KeycloakSsoProvisionedUser::STATUS_DELETED,
        ], ['accessibleFields' => ['*' => true]]);
        $table->saveOrFail($provenance);

        $outcome = $this->service($actor->id, $this->eligibleUserResponses())->process($this->event());

        $this->assertSame(ProvisionKeycloakUserService::OUTCOME_DUPLICATE, $outcome);
        $this->assertSame(KeycloakSsoProvisioningEvent::STATUS_SKIPPED, $this->savedEventStatus());
        $this->assertSame('subject_already_provisioned', $this->savedEventFailureCode());
        $this->assertSame(1, TableRegistry::getTableLocator()->get('Users')->find()->where([
            'LOWER(Users.username)' => 'new.user@example.test',
        ])->count());
    }

    public function testDuplicateEventDoesNotFetchKeycloakOrCreateSecondUser(): void
    {
        RoleFactory::make()->user()->persist();
        $actor = UserFactory::make()->admin()->active()->notDisabled()->persist();
        $this->assertInstanceOf(User::class, $actor);
        $http = new QueuedOidcHttpClient($this->eligibleUserResponses());
        $service = $this->serviceWithHttp($actor->id, $http);

        $this->assertSame(ProvisionKeycloakUserService::OUTCOME_PROVISIONED, $service->process($this->event()));
        $this->assertSame(ProvisionKeycloakUserService::OUTCOME_DUPLICATE, $service->process($this->event()));
        $this->assertCount(2, $http->requests);
        $this->assertSame(1, TableRegistry::getTableLocator()->get('Users')->find()->where([
            'username' => 'new.user@example.test',
        ])->count());
    }

    public function testInactiveActorFailsWithoutCreatingUser(): void
    {
        RoleFactory::make()->user()->persist();
        $actor = UserFactory::make()->admin()->inactive()->notDisabled()->persist();
        $this->assertInstanceOf(User::class, $actor);

        $outcome = $this->service($actor->id, $this->eligibleUserResponses())->process($this->event());

        $this->assertSame(ProvisionKeycloakUserService::OUTCOME_FAILED, $outcome);
        $this->assertSame(KeycloakSsoProvisioningEvent::STATUS_FAILED, $this->savedEventStatus());
        $this->assertSame(0, TableRegistry::getTableLocator()->get('Users')->find()->where([
            'username' => 'new.user@example.test',
        ])->count());
    }

    public function testExistingUsernameWithDifferentCaseFailsClosedAsCollision(): void
    {
        RoleFactory::make()->user()->persist();
        $actor = UserFactory::make()->admin()->active()->notDisabled()->persist();
        $this->assertInstanceOf(User::class, $actor);
        UserFactory::make(['username' => 'NEW.USER@example.test'])->user()->active()->persist();

        $outcome = $this->service($actor->id, $this->eligibleUserResponses())->process($this->event());

        $this->assertSame(ProvisionKeycloakUserService::OUTCOME_COLLISION, $outcome);
        $this->assertSame(KeycloakSsoProvisioningEvent::STATUS_COLLISION, $this->savedEventStatus());
    }

    public function testDisabledNondeletedUsernameStillFailsClosedAsCollision(): void
    {
        RoleFactory::make()->user()->persist();
        $actor = UserFactory::make()->admin()->active()->notDisabled()->persist();
        $this->assertInstanceOf(User::class, $actor);
        UserFactory::make(['username' => 'new.user@example.test'])
            ->user()
            ->active()
            ->disabled()
            ->persist();

        $outcome = $this->service($actor->id, $this->eligibleUserResponses())->process($this->event());

        $this->assertSame(ProvisionKeycloakUserService::OUTCOME_COLLISION, $outcome);
        $this->assertSame(KeycloakSsoProvisioningEvent::STATUS_COLLISION, $this->savedEventStatus());
        $this->assertSame('email_collision', $this->savedEventFailureCode());
    }

    public function testLaterVerifiedUpdateCanProvisionAfterUnverifiedCreateWasSkipped(): void
    {
        RoleFactory::make()->user()->persist();
        $actor = UserFactory::make()->admin()->active()->notDisabled()->persist();
        $this->assertInstanceOf(User::class, $actor);
        $unverified = $this->eligibleUserResponses()[1];
        $unverified['emailVerified'] = false;
        $verified = $this->eligibleUserResponses()[1];
        $http = new QueuedOidcHttpClient([
            ['access_token' => 'service-token', 'token_type' => 'Bearer'],
            $unverified,
            $verified,
        ]);
        $service = $this->serviceWithHttp($actor->id, $http);

        $this->assertSame(ProvisionKeycloakUserService::OUTCOME_SKIPPED, $service->process($this->event()));
        $this->assertSame(
            ProvisionKeycloakUserService::OUTCOME_PROVISIONED,
            $service->process($this->event('4d2d5c43-a76a-5d4a-8f47-2b1f0268e3d6', 'UPDATE'))
        );
        $this->assertSame(1, TableRegistry::getTableLocator()->get('Users')->find()->where([
            'username' => 'new.user@example.test',
        ])->count());
    }

    public function testDryRunDoesNotPersistCheckpointUserTokenOrProvenance(): void
    {
        RoleFactory::make()->user()->persist();
        $actor = UserFactory::make()->admin()->active()->notDisabled()->persist();
        $this->assertInstanceOf(User::class, $actor);

        $outcome = $this->service($actor->id, $this->eligibleUserResponses())->process($this->event(), true);

        $this->assertSame(ProvisionKeycloakUserService::OUTCOME_WOULD_PROVISION, $outcome);
        $this->assertSame(0, TableRegistry::getTableLocator()
            ->get('Passbolt/KeycloakSso.KeycloakSsoProvisioningEvents')->find()->count());
        $this->assertSame(0, TableRegistry::getTableLocator()
            ->get('Passbolt/KeycloakSso.KeycloakSsoProvisionedUsers')->find()->count());
        $this->assertSame(0, TableRegistry::getTableLocator()->get('Users')->find()->where([
            'username' => 'new.user@example.test',
        ])->count());
    }

    /** @param list<array<mixed>|\Throwable> $responses */
    private function service(string $actorId, array $responses): ProvisionKeycloakUserService
    {
        return $this->serviceWithHttp($actorId, new QueuedOidcHttpClient($responses));
    }

    private function serviceWithHttp(
        string $actorId,
        QueuedOidcHttpClient $http
    ): ProvisionKeycloakUserService {
        $configuration = new ProvisioningConfigurationDto(
            'https://keyclock.gobaz.ir/realms/passbolt',
            'https://keyclock.gobaz.ir/admin/realms/passbolt',
            'passbolt-provisioning',
            'provisioning-secret',
            $actorId,
            86_400,
            300,
            100
        );
        $discovery = new OidcDiscoveryDocument(
            $configuration->issuer,
            $configuration->issuer . '/protocol/openid-connect/auth',
            $configuration->issuer . '/protocol/openid-connect/token',
            $configuration->issuer . '/protocol/openid-connect/certs'
        );

        return new ProvisionKeycloakUserService(
            $configuration,
            new KeycloakProvisioningApiService($configuration, $discovery, $http),
            new ProvisioningAuditService()
        );
    }

    /** @return list<array<mixed>> */
    private function eligibleUserResponses(): array
    {
        return [
            ['access_token' => 'service-token', 'token_type' => 'Bearer'],
            [
                'id' => $this->event()->subject,
                'email' => 'New.User@example.test',
                'emailVerified' => true,
                'enabled' => true,
                'firstName' => 'New',
                'lastName' => 'User',
            ],
        ];
    }

    private function event(
        string $eventId = '7cd5488d-b1ec-42f6-925d-795620ff2701',
        string $operation = 'CREATE'
    ): KeycloakAdminEventDto {
        return new KeycloakAdminEventDto(
            $eventId,
            1_789_569_606_000,
            $operation,
            'e2bc1228-043a-4512-8a91-f08683e55e53'
        );
    }

    private function savedEventStatus(): string
    {
        return (string)TableRegistry::getTableLocator()
            ->get('Passbolt/KeycloakSso.KeycloakSsoProvisioningEvents')
            ->find()->firstOrFail()->get('status');
    }

    private function savedEventFailureCode(): string
    {
        return (string)TableRegistry::getTableLocator()
            ->get('Passbolt/KeycloakSso.KeycloakSsoProvisioningEvents')
            ->find()->firstOrFail()->get('failure_code');
    }
}
