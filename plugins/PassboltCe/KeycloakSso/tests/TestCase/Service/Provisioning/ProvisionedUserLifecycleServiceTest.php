<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Service\Provisioning;

use App\Controller\Users\UsersDeleteController;
use App\Model\Entity\Group;
use App\Model\Entity\Secret;
use App\Model\Entity\User;
use App\Service\Resources\ResourcesExpireResourcesFallbackServiceService;
use App\Service\Resources\ResourcesExpireResourcesServiceInterface;
use App\Test\Factory\GroupFactory;
use App\Test\Factory\GroupsUserFactory;
use App\Test\Factory\ResourceFactory;
use App\Test\Factory\UserFactory;
use App\Utility\UuidFactory;
use Cake\Event\EventList;
use Cake\Event\EventManager;
use Cake\I18n\DateTime;
use Cake\ORM\Table;
use Cake\ORM\TableRegistry;
use Passbolt\KeycloakSso\Error\Exception\OidcHttpStatusException;
use Passbolt\KeycloakSso\Error\Exception\ProvisioningException;
use Passbolt\KeycloakSso\Model\Dto\DeprovisioningConfigurationDto;
use Passbolt\KeycloakSso\Model\Dto\OidcDiscoveryDocument;
use Passbolt\KeycloakSso\Model\Dto\PendingIdentityLink;
use Passbolt\KeycloakSso\Model\Dto\ProvisioningConfigurationDto;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoGroupMembership;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoProvisionedUser;
use Passbolt\KeycloakSso\Service\Identity\IdentityLinkPersistenceService;
use Passbolt\KeycloakSso\Service\Provisioning\KeycloakProvisioningApiService;
use Passbolt\KeycloakSso\Service\Provisioning\ManagedGroupAccessRemovalService;
use Passbolt\KeycloakSso\Service\Provisioning\ProvisionedUserDeletionService;
use Passbolt\KeycloakSso\Service\Provisioning\ProvisionedUserLifecycleService;
use Passbolt\KeycloakSso\Test\Lib\KeycloakSsoIntegrationTestCase;
use Passbolt\KeycloakSso\Test\Utility\QueuedOidcHttpClient;
use RuntimeException;

final class ProvisionedUserLifecycleServiceTest extends KeycloakSsoIntegrationTestCase
{
    private const ISSUER = 'https://keyclock.gobaz.ir/realms/passbolt';
    private const SUBJECT = 'e2bc1228-043a-4512-8a91-f08683e55e53';

    public function testDisabledKeycloakUserIsDisabledAndIdentityIsRevoked(): void
    {
        [$actor, $user] = $this->users();
        (new IdentityLinkPersistenceService())->create($user->id, new PendingIdentityLink(
            self::ISSUER,
            self::SUBJECT,
            $user->username
        ));
        $service = $this->lifecycleService($actor, [$this->remoteUser(false)]);

        $counts = $service->run(false, new DateTime('2026-10-06 12:00:00'));

        $this->assertSame(1, $counts[ProvisionedUserLifecycleService::OUTCOME_DEPROVISIONED]);
        $this->assertTrue($this->userById($user->id)->isDisabled());
        $this->assertFalse(TableRegistry::getTableLocator()->get(
            'Passbolt/KeycloakSso.KeycloakSsoIdentities'
        )->exists(['user_id' => $user->id]));
        $provisioned = $this->provisionedUsers()->find()->firstOrFail();
        $this->assertSame(KeycloakSsoProvisionedUser::STATUS_DEPROVISIONED, $provisioned->get('lifecycle_status'));
        $this->assertSame(KeycloakSsoProvisionedUser::REASON_DISABLED, $provisioned->get('deprovision_reason'));
        $this->assertNull($provisioned->get('deletion_eligible_at'));
        $this->assertInstanceOf(DateTime::class, $provisioned->get('managed_disabled_at'));
    }

    public function testDisablingUserAppliesConfiguredResourceExpiryPolicy(): void
    {
        [$actor, $user] = $this->users();
        ResourceFactory::make()->withSecretRevisions()->withSecretsFor([$user])->persist();
        $expiry = $this->createMock(ResourcesExpireResourcesServiceInterface::class);
        $expiry->expects($this->once())->method('expireResourcesForSecrets')->with(
            $this->callback(
                fn (array $secrets): bool => count($secrets) === 1 && array_values($secrets)[0] instanceof Secret
            )
        )->willReturn(true);

        $counts = $this->lifecycleService($actor, [$this->remoteUser(false)], $expiry)->run();

        $this->assertSame(1, $counts[ProvisionedUserLifecycleService::OUTCOME_DEPROVISIONED]);
        $this->assertTrue($this->userById($user->id)->isDisabled());
    }

    public function testDeprovisioningRemovesManagedGroupAccessWithResourceExpiry(): void
    {
        [$actor, $user] = $this->users();
        $group = GroupFactory::make()->withGroupsManagersFor([$actor])->persist();
        self::assertInstanceOf(Group::class, $group);
        GroupsUserFactory::make([
            'group_id' => $group->id,
            'user_id' => $user->id,
            'is_admin' => false,
            'created_by' => $actor->id,
            'modified_by' => $actor->id,
        ])->persist();
        $mapping = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoProvisionedGroups')->newEntity([
            'id' => UuidFactory::uuid(),
            'group_id' => $group->id,
            'issuer' => self::ISSUER,
            'keycloak_group_id' => 'engineering-id',
            'keycloak_group_path' => '/Engineering',
        ], ['accessibleFields' => ['*' => true]]);
        $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoProvisionedGroups')->saveOrFail($mapping);
        $membership = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoGroupMemberships')->newEntity([
            'id' => UuidFactory::uuid(),
            'provisioned_group_id' => $mapping->get('id'),
            'user_id' => $user->id,
            'status' => KeycloakSsoGroupMembership::STATUS_ACTIVE,
            'failure_code' => null,
        ], ['accessibleFields' => ['*' => true]]);
        $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoGroupMemberships')->saveOrFail($membership);
        ResourceFactory::make()
            ->withSecretRevisions()
            ->withPermissionsFor([$group])
            ->withSecretsFor([$user])
            ->persist();
        $expiry = $this->createMock(ResourcesExpireResourcesServiceInterface::class);
        $expiry->expects($this->exactly(2))->method('expireResourcesForSecrets')->willReturn(true);

        $counts = $this->lifecycleService($actor, [$this->remoteUser(false)], $expiry)->run();

        $this->assertSame(1, $counts[ProvisionedUserLifecycleService::OUTCOME_DEPROVISIONED]);
        $this->assertFalse($this->fetchTable('GroupsUsers')->exists([
            'group_id' => $group->id,
            'user_id' => $user->id,
        ]));
        $this->assertSame(
            KeycloakSsoGroupMembership::STATUS_REVOKED,
            $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoGroupMemberships')
                ->get($membership->get('id'))
                ->get('status')
        );
    }

    public function testResourceExpiryFailureCannotRollBackUserDisable(): void
    {
        [$actor, $user] = $this->users();
        ResourceFactory::make()->withSecretRevisions()->withSecretsFor([$user])->persist();
        $expiry = $this->createMock(ResourcesExpireResourcesServiceInterface::class);
        $expiry->expects($this->once())->method('expireResourcesForSecrets')
            ->willThrowException(new RuntimeException('expiry unavailable'));

        $counts = $this->lifecycleService($actor, [$this->remoteUser(false)], $expiry)->run();

        $this->assertSame(1, $counts[ProvisionedUserLifecycleService::OUTCOME_FAILED]);
        $this->assertTrue($this->userById($user->id)->isDisabled());
        $this->assertSame(
            KeycloakSsoProvisionedUser::STATUS_DEPROVISIONING,
            $this->provisionedUsers()->find()->firstOrFail()->get('lifecycle_status')
        );
    }

    public function testExactNotFoundQuarantinesBeforeDeletion(): void
    {
        [$actor, $user] = $this->users();
        $now = new DateTime('2026-10-06 12:00:00');

        $counts = $this->lifecycleService($actor, [new OidcHttpStatusException(404)])->run(false, $now);

        $this->assertSame(1, $counts[ProvisionedUserLifecycleService::OUTCOME_DEPROVISIONED]);
        $provisioned = $this->provisionedUsers()->find()->firstOrFail();
        $this->assertSame(KeycloakSsoProvisionedUser::STATUS_QUARANTINED, $provisioned->get('lifecycle_status'));
        $this->assertSame(KeycloakSsoProvisionedUser::REASON_DELETED, $provisioned->get('deprovision_reason'));
        $this->assertSame(
            $now->addSeconds(3_600)->toDateTimeString(),
            $provisioned->get('deletion_eligible_at')->toDateTimeString()
        );
        $this->assertTrue($this->userById($user->id)->isDisabled());
    }

    public function testProviderFailureNeverDeprovisions(): void
    {
        [$actor, $user] = $this->users();

        $counts = $this->lifecycleService($actor, [new OidcHttpStatusException(503)])->run();

        $this->assertSame(1, $counts[ProvisionedUserLifecycleService::OUTCOME_FAILED]);
        $this->assertFalse($this->userById($user->id)->isDisabled());
        $this->assertSame(
            KeycloakSsoProvisionedUser::STATUS_ACTIVE,
            $this->provisionedUsers()->find()->firstOrFail()->get('lifecycle_status')
        );
    }

    public function testDryRunDoesNotDisableOrChangeLifecycleState(): void
    {
        [$actor, $user] = $this->users();

        $counts = $this->lifecycleService($actor, [new OidcHttpStatusException(404)])->run(true);

        $this->assertSame(1, $counts[ProvisionedUserLifecycleService::OUTCOME_WOULD_DEPROVISION]);
        $this->assertFalse($this->userById($user->id)->isDisabled());
        $this->assertSame(
            KeycloakSsoProvisionedUser::STATUS_ACTIVE,
            $this->provisionedUsers()->find()->firstOrFail()->get('lifecycle_status')
        );
    }

    public function testLifecycleNeverTouchesProvisioningFromAnotherIssuer(): void
    {
        [$actor] = $this->users();
        $foreignUser = UserFactory::make(['username' => 'foreign@example.test'])
            ->user()->active()->notDisabled()->persist();
        self::assertInstanceOf(User::class, $foreignUser);
        $foreign = $this->provisionedUsers()->newEntity([
            'id' => UuidFactory::uuid(),
            'user_id' => $foreignUser->id,
            'issuer' => 'https://keyclock.gobaz.ir/realms/foreign',
            'subject' => 'foreign-subject',
            'email_at_provisioning' => $foreignUser->username,
            'source_event_id' => UuidFactory::uuid(),
            'lifecycle_status' => KeycloakSsoProvisionedUser::STATUS_ACTIVE,
        ], ['accessibleFields' => ['*' => true]]);
        $this->provisionedUsers()->saveOrFail($foreign);

        $counts = $this->lifecycleService($actor, [$this->remoteUser(true)])->run();

        $this->assertSame(1, $counts[ProvisionedUserLifecycleService::OUTCOME_ACTIVE]);
        $this->assertFalse($this->userById($foreignUser->id)->isDisabled());
        $this->assertSame(
            KeycloakSsoProvisionedUser::STATUS_ACTIVE,
            $this->provisionedUsers()->get($foreign->get('id'))->get('lifecycle_status')
        );
    }

    public function testConcurrentFreshClaimDoesNotRunCleanupTwice(): void
    {
        [$actor, $user] = $this->users(true, KeycloakSsoProvisionedUser::STATUS_DEPROVISIONING);
        $this->provisionedUsers()->updateAll([
            'deprovision_reason' => KeycloakSsoProvisionedUser::REASON_DISABLED,
            'modified' => DateTime::now(),
        ], ['user_id' => $user->id]);

        $counts = $this->lifecycleService($actor, [$this->remoteUser(false)])->run();

        $this->assertSame(1, $counts[ProvisionedUserLifecycleService::OUTCOME_IN_PROGRESS]);
        $this->assertSame(
            KeycloakSsoProvisionedUser::STATUS_DEPROVISIONING,
            $this->provisionedUsers()->find()->firstOrFail()->get('lifecycle_status')
        );
        $this->assertTrue($this->userById($user->id)->isDisabled());
    }

    public function testReappearingUserIsNotAutomaticallyReenabled(): void
    {
        [$actor, $user] = $this->users(true, KeycloakSsoProvisionedUser::STATUS_QUARANTINED);
        $this->provisionedUsers()->updateAll([
            'deprovision_reason' => KeycloakSsoProvisionedUser::REASON_DELETED,
            'absent_since' => DateTime::yesterday(),
            'deletion_eligible_at' => DateTime::yesterday(),
        ], ['user_id' => $user->id]);

        $counts = $this->lifecycleService($actor, [$this->remoteUser(true)], null, true)->run();

        $this->assertSame(1, $counts[ProvisionedUserLifecycleService::OUTCOME_REACTIVATION_REQUIRED]);
        $this->assertTrue($this->userById($user->id)->isDisabled());
        $provisioned = $this->provisionedUsers()->find()->firstOrFail();
        $this->assertSame(
            KeycloakSsoProvisionedUser::STATUS_REACTIVATION_REQUIRED,
            $provisioned->get('lifecycle_status')
        );
        $this->assertNull($provisioned->get('absent_since'));
        $this->assertNull($provisioned->get('deletion_eligible_at'));
    }

    public function testPassboltDisabledUserIsNeverAutomaticallyReenabled(): void
    {
        [$actor, $user] = $this->users(true, KeycloakSsoProvisionedUser::STATUS_ACTIVE);

        $counts = $this->lifecycleService($actor, [$this->remoteUser(true)], null, true)->run();

        $this->assertSame(1, $counts[ProvisionedUserLifecycleService::OUTCOME_REACTIVATION_REQUIRED]);
        $this->assertTrue($this->userById($user->id)->isDisabled());
        $this->assertSame(
            KeycloakSsoProvisionedUser::STATUS_REACTIVATION_REQUIRED,
            $this->provisionedUsers()->find()->firstOrFail()->get('lifecycle_status')
        );
    }

    public function testManagedKeycloakSuspensionIsAutomaticallyReactivatedWhenExplicitlyEnabled(): void
    {
        [$actor, $user] = $this->users();
        (new IdentityLinkPersistenceService())->create($user->id, new PendingIdentityLink(
            self::ISSUER,
            self::SUBJECT,
            $user->username
        ));
        $now = new DateTime('2026-10-11 12:00:00');
        $this->lifecycleService($actor, [$this->remoteUser(false)], null, true)->run(false, $now);

        $counts = $this->lifecycleService($actor, [$this->remoteUser(true)], null, true)
            ->run(false, $now->addMinutes(1));

        $this->assertSame(1, $counts[ProvisionedUserLifecycleService::OUTCOME_REACTIVATED]);
        $this->assertFalse($this->userById($user->id)->isDisabled());
        $provisioned = $this->provisionedUsers()->find()->firstOrFail();
        $this->assertSame(KeycloakSsoProvisionedUser::STATUS_ACTIVE, $provisioned->get('lifecycle_status'));
        $this->assertNull($provisioned->get('deprovision_reason'));
        $this->assertNull($provisioned->get('deprovisioned_at'));
        $this->assertNull($provisioned->get('managed_disabled_at'));
        $this->assertFalse($this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoIdentities')->exists([
            'user_id' => $user->id,
        ]));
    }

    public function testManagedReactivationDryRunDoesNotEnableUser(): void
    {
        [$actor, $user] = $this->users();
        $this->lifecycleService($actor, [$this->remoteUser(false)], null, true)->run();

        $counts = $this->lifecycleService($actor, [$this->remoteUser(true)], null, true)->run(true);

        $this->assertSame(1, $counts[ProvisionedUserLifecycleService::OUTCOME_WOULD_REACTIVATE]);
        $this->assertTrue($this->userById($user->id)->isDisabled());
        $this->assertSame(
            KeycloakSsoProvisionedUser::STATUS_DEPROVISIONED,
            $this->provisionedUsers()->find()->firstOrFail()->get('lifecycle_status')
        );
    }

    public function testManagedSuspensionRequiresReviewWhenAutomaticReactivationIsDisabled(): void
    {
        [$actor, $user] = $this->users();
        $this->lifecycleService($actor, [$this->remoteUser(false)], null, true)->run();

        $counts = $this->lifecycleService($actor, [$this->remoteUser(true)])->run();

        $this->assertSame(1, $counts[ProvisionedUserLifecycleService::OUTCOME_REACTIVATION_REQUIRED]);
        $this->assertTrue($this->userById($user->id)->isDisabled());
        $this->assertSame(
            KeycloakSsoProvisionedUser::STATUS_DEPROVISIONED,
            $this->provisionedUsers()->find()->firstOrFail()->get('lifecycle_status')
        );
    }

    public function testEnablingPolicyLaterCanReactivateACompletedManagedSuspension(): void
    {
        [$actor, $user] = $this->users();
        $this->lifecycleService($actor, [$this->remoteUser(false)], null, true)->run();
        $this->lifecycleService($actor, [$this->remoteUser(true)])->run();

        $counts = $this->lifecycleService($actor, [$this->remoteUser(true)], null, true)->run();

        $this->assertSame(1, $counts[ProvisionedUserLifecycleService::OUTCOME_REACTIVATED]);
        $this->assertFalse($this->userById($user->id)->isDisabled());
    }

    public function testExistingPassboltSuspensionIsNeverAdoptedForAutomaticReactivation(): void
    {
        [$actor, $user] = $this->users(true);
        $this->lifecycleService($actor, [$this->remoteUser(false)], null, true)->run();
        $this->assertNull($this->provisionedUsers()->find()->firstOrFail()->get('managed_disabled_at'));

        $counts = $this->lifecycleService($actor, [$this->remoteUser(true)], null, true)->run();

        $this->assertSame(1, $counts[ProvisionedUserLifecycleService::OUTCOME_REACTIVATION_REQUIRED]);
        $this->assertTrue($this->userById($user->id)->isDisabled());
    }

    public function testChangedPassboltSuspensionIsNeverAutomaticallyReactivated(): void
    {
        [$actor, $user] = $this->users();
        $this->lifecycleService($actor, [$this->remoteUser(false)], null, true)->run();
        $this->fetchTable('Users')->updateAll(['disabled' => DateTime::yesterday()], ['id' => $user->id]);

        $counts = $this->lifecycleService($actor, [$this->remoteUser(true)], null, true)->run();

        $this->assertSame(1, $counts[ProvisionedUserLifecycleService::OUTCOME_REACTIVATION_REQUIRED]);
        $this->assertTrue($this->userById($user->id)->isDisabled());
    }

    public function testReviewRequiredSuspensionIsNeverAutomaticallyReactivated(): void
    {
        [$actor, $user] = $this->users();
        $this->lifecycleService($actor, [$this->remoteUser(false)], null, true)->run();
        $this->provisionedUsers()->updateAll([
            'lifecycle_status' => KeycloakSsoProvisionedUser::STATUS_REACTIVATION_REQUIRED,
        ], ['user_id' => $user->id]);

        $counts = $this->lifecycleService($actor, [$this->remoteUser(true)], null, true)->run();

        $this->assertSame(1, $counts[ProvisionedUserLifecycleService::OUTCOME_REACTIVATION_REQUIRED]);
        $this->assertTrue($this->userById($user->id)->isDisabled());
    }

    public function testIncompleteDeprovisioningCleanupIsNeverAutomaticallyReactivated(): void
    {
        [$actor, $user] = $this->users();
        ResourceFactory::make()->withSecretRevisions()->withSecretsFor([$user])->persist();
        $expiry = $this->createMock(ResourcesExpireResourcesServiceInterface::class);
        $expiry->expects($this->once())->method('expireResourcesForSecrets')
            ->willThrowException(new RuntimeException('expiry unavailable'));
        $this->lifecycleService($actor, [$this->remoteUser(false)], $expiry, true)->run();

        $counts = $this->lifecycleService($actor, [$this->remoteUser(true)], null, true)->run();

        $this->assertSame(1, $counts[ProvisionedUserLifecycleService::OUTCOME_REACTIVATION_REQUIRED]);
        $this->assertTrue($this->userById($user->id)->isDisabled());
        $this->assertSame(
            KeycloakSsoProvisionedUser::STATUS_REACTIVATION_REQUIRED,
            $this->provisionedUsers()->find()->firstOrFail()->get('lifecycle_status')
        );
    }

    public function testManagedReactivationRequiresAnActiveSeparateAdministratorActor(): void
    {
        [$actor, $user] = $this->users();
        $this->lifecycleService($actor, [$this->remoteUser(false)], null, true)->run();
        $this->fetchTable('Users')->updateAll(['disabled' => DateTime::now()], ['id' => $actor->id]);

        $counts = $this->lifecycleService($actor, [$this->remoteUser(true)], null, true)->run();

        $this->assertSame(1, $counts[ProvisionedUserLifecycleService::OUTCOME_FAILED]);
        $this->assertTrue($this->userById($user->id)->isDisabled());
        $this->assertSame(
            KeycloakSsoProvisionedUser::STATUS_DEPROVISIONED,
            $this->provisionedUsers()->find()->firstOrFail()->get('lifecycle_status')
        );
    }

    public function testNewAbsenceAfterDisabledObservationStartsFreshDeletionGrace(): void
    {
        [$actor, $user] = $this->users(true, KeycloakSsoProvisionedUser::STATUS_DEPROVISIONED);
        $this->provisionedUsers()->updateAll([
            'deprovision_reason' => KeycloakSsoProvisionedUser::REASON_DISABLED,
            'absent_since' => null,
            'deletion_eligible_at' => null,
        ], ['user_id' => $user->id]);
        $now = new DateTime('2026-10-07 12:00:00');

        $counts = $this->lifecycleService($actor, [new OidcHttpStatusException(404)])->run(false, $now);

        $this->assertSame(1, $counts[ProvisionedUserLifecycleService::OUTCOME_DEPROVISIONED]);
        $provisioned = $this->provisionedUsers()->find()->firstOrFail();
        $this->assertSame($now->toDateTimeString(), $provisioned->get('absent_since')->toDateTimeString());
        $this->assertSame(
            $now->addSeconds(3_600)->toDateTimeString(),
            $provisioned->get('deletion_eligible_at')->toDateTimeString()
        );
    }

    public function testDeletionRequiresFreshAbsenceGraceAndExplicitConfirmation(): void
    {
        [$actor, $user] = $this->users(true, KeycloakSsoProvisionedUser::STATUS_QUARANTINED);
        $this->provisionedUsers()->updateAll([
            'deprovision_reason' => KeycloakSsoProvisionedUser::REASON_DELETED,
            'deprovisioned_at' => DateTime::yesterday(),
            'absent_since' => DateTime::yesterday(),
            'deletion_eligible_at' => DateTime::yesterday(),
        ], ['user_id' => $user->id]);
        $api = $this->api($actor, [new OidcHttpStatusException(404)]);
        $expiry = $this->createMock(ResourcesExpireResourcesServiceInterface::class);
        $expiry->expects($this->once())->method('expireResourcesForSecrets')->willReturn(true);
        $service = new ProvisionedUserDeletionService(
            $this->lifecycleConfiguration($actor),
            $api,
            $expiry
        );
        $eventManager = new EventManager();
        $eventManager->setEventList(new EventList());
        $service->setEventManager($eventManager);

        $service->delete(
            $user->id,
            ProvisionedUserDeletionService::CONFIRMATION
        );

        $this->assertEventFired(UsersDeleteController::DELETE_SUCCESS_EVENT_NAME, $eventManager);
        $this->assertTrue($this->userById($user->id)->isDeleted());
        $this->assertSame(
            KeycloakSsoProvisionedUser::STATUS_DELETED,
            $this->provisionedUsers()->find()->firstOrFail()->get('lifecycle_status')
        );
    }

    public function testDeletionRejectsPresentKeycloakUser(): void
    {
        [$actor, $user] = $this->users(true, KeycloakSsoProvisionedUser::STATUS_QUARANTINED);
        $this->makeDeletionEligible($user);

        $this->expectException(ProvisioningException::class);
        (new ProvisionedUserDeletionService(
            $this->lifecycleConfiguration($actor),
            $this->api($actor, [$this->remoteUser(true)]),
            new ResourcesExpireResourcesFallbackServiceService()
        ))->delete($user->id, ProvisionedUserDeletionService::CONFIRMATION);
    }

    public function testDeletionRejectsUnavailableUserDirectoryBeforeInterpretingAbsence(): void
    {
        [$actor, $user] = $this->users(true, KeycloakSsoProvisionedUser::STATUS_QUARANTINED);
        $this->makeDeletionEligible($user);
        $service = new ProvisionedUserDeletionService(
            $this->lifecycleConfiguration($actor),
            $this->api($actor, [], new OidcHttpStatusException(404)),
            new ResourcesExpireResourcesFallbackServiceService()
        );

        try {
            $service->delete($user->id, ProvisionedUserDeletionService::CONFIRMATION);
            $this->fail('A failed user-directory preflight must reject deletion.');
        } catch (OidcHttpStatusException) {
            $this->assertFalse($this->userById($user->id)->isDeleted());
        }
    }

    public function testDeletionRejectsBeforeGraceExpires(): void
    {
        [$actor, $user] = $this->users(true, KeycloakSsoProvisionedUser::STATUS_QUARANTINED);
        $now = new DateTime('2026-10-07 12:00:00');
        $this->provisionedUsers()->updateAll([
            'deprovision_reason' => KeycloakSsoProvisionedUser::REASON_DELETED,
            'deprovisioned_at' => $now,
            'absent_since' => $now,
            'deletion_eligible_at' => $now->addSeconds(3_600),
        ], ['user_id' => $user->id]);

        $this->expectException(ProvisioningException::class);
        (new ProvisionedUserDeletionService(
            $this->lifecycleConfiguration($actor),
            $this->api($actor, [new OidcHttpStatusException(404)]),
            new ResourcesExpireResourcesFallbackServiceService()
        ))->delete($user->id, ProvisionedUserDeletionService::CONFIRMATION, $now);
    }

    public function testDeletionRejectsWithoutExactConfirmation(): void
    {
        [$actor, $user] = $this->users(true, KeycloakSsoProvisionedUser::STATUS_QUARANTINED);
        $this->makeDeletionEligible($user);

        $this->expectException(ProvisioningException::class);
        (new ProvisionedUserDeletionService(
            $this->lifecycleConfiguration($actor),
            $this->api($actor, []),
            new ResourcesExpireResourcesFallbackServiceService()
        ))->delete($user->id, 'delete');
    }

    public function testDeletionRejectsConfiguredProvisioningActor(): void
    {
        [$actor] = $this->users(true, KeycloakSsoProvisionedUser::STATUS_QUARANTINED);
        $this->expectException(ProvisioningException::class);

        (new ProvisionedUserDeletionService(
            $this->lifecycleConfiguration($actor),
            $this->api($actor, []),
            new ResourcesExpireResourcesFallbackServiceService()
        ))->delete($actor->id, ProvisionedUserDeletionService::CONFIRMATION);
    }

    /** @return array{0: User, 1: User} */
    private function users(bool $disabled = false, string $status = KeycloakSsoProvisionedUser::STATUS_ACTIVE): array
    {
        $actor = UserFactory::make()->admin()->active()->notDisabled()->persist();
        $factory = UserFactory::make(['username' => 'managed@example.test'])->user()->active();
        $user = ($disabled ? $factory->disabled() : $factory->notDisabled())->persist();
        self::assertInstanceOf(User::class, $actor);
        self::assertInstanceOf(User::class, $user);
        $provisioned = $this->provisionedUsers()->newEntity([
            'id' => UuidFactory::uuid(),
            'user_id' => $user->id,
            'issuer' => self::ISSUER,
            'subject' => self::SUBJECT,
            'email_at_provisioning' => $user->username,
            'source_event_id' => UuidFactory::uuid(),
            'lifecycle_status' => $status,
        ], ['accessibleFields' => ['*' => true]]);
        $this->provisionedUsers()->saveOrFail($provisioned);

        return [$actor, $user];
    }

    /** @return array<string, mixed> */
    private function remoteUser(bool $enabled): array
    {
        return [
            'id' => self::SUBJECT,
            'email' => 'managed@example.test',
            'emailVerified' => true,
            'enabled' => $enabled,
            'firstName' => 'Managed',
            'lastName' => 'User',
        ];
    }

    private function lifecycleService(
        User $actor,
        array $responses,
        ?ResourcesExpireResourcesServiceInterface $resourcesExpiry = null,
        bool $reactivationEnabled = false,
    ): ProvisionedUserLifecycleService {
        $resourcesExpiry ??= new ResourcesExpireResourcesFallbackServiceService();

        return new ProvisionedUserLifecycleService(
            $this->lifecycleConfiguration($actor, $reactivationEnabled),
            $this->api($actor, $responses),
            new ManagedGroupAccessRemovalService($resourcesExpiry),
            $resourcesExpiry
        );
    }

    private function lifecycleConfiguration(
        User $actor,
        bool $reactivationEnabled = false
    ): DeprovisioningConfigurationDto {
        return new DeprovisioningConfigurationDto(
            self::ISSUER,
            $actor->id,
            100,
            3_600,
            $reactivationEnabled
        );
    }

    private function api(
        User $actor,
        array $responses,
        mixed $directoryPreflight = [],
    ): KeycloakProvisioningApiService {
        return new KeycloakProvisioningApiService(
            new ProvisioningConfigurationDto(
                self::ISSUER,
                'https://keyclock.gobaz.ir/admin/realms/passbolt',
                'passbolt-provisioning',
                'provisioning-secret',
                $actor->id,
                86_400,
                300,
                100
            ),
            new OidcDiscoveryDocument(
                self::ISSUER,
                self::ISSUER . '/protocol/openid-connect/auth',
                self::ISSUER . '/protocol/openid-connect/token',
                self::ISSUER . '/protocol/openid-connect/certs'
            ),
            new QueuedOidcHttpClient(array_merge(
                [
                    ['access_token' => 'service-token', 'token_type' => 'Bearer'],
                    $directoryPreflight,
                ],
                $responses
            ))
        );
    }

    private function userById(string $id): User
    {
        $user = TableRegistry::getTableLocator()->get('Users')->get($id);
        self::assertInstanceOf(User::class, $user);

        return $user;
    }

    private function provisionedUsers(): Table
    {
        return TableRegistry::getTableLocator()->get('Passbolt/KeycloakSso.KeycloakSsoProvisionedUsers');
    }

    private function makeDeletionEligible(User $user): void
    {
        $this->provisionedUsers()->updateAll([
            'deprovision_reason' => KeycloakSsoProvisionedUser::REASON_DELETED,
            'deprovisioned_at' => DateTime::yesterday(),
            'absent_since' => DateTime::yesterday(),
            'deletion_eligible_at' => DateTime::yesterday(),
        ], ['user_id' => $user->id]);
    }
}
