<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Service\Provisioning;

use App\Model\Entity\Group;
use App\Model\Entity\Role;
use App\Model\Entity\Secret;
use App\Model\Entity\User;
use App\Service\GroupsUsers\GroupsUsersAddService;
use App\Service\Resources\ResourcesExpireResourcesFallbackServiceService;
use App\Service\Resources\ResourcesExpireResourcesServiceInterface;
use App\Test\Factory\GroupFactory;
use App\Test\Factory\ResourceFactory;
use App\Test\Factory\UserFactory;
use App\Utility\UserAccessControl;
use App\Utility\UuidFactory;
use Cake\ORM\Table;
use Cake\ORM\TableRegistry;
use Passbolt\KeycloakSso\Error\Exception\OidcNetworkException;
use Passbolt\KeycloakSso\Model\Dto\OidcDiscoveryDocument;
use Passbolt\KeycloakSso\Model\Dto\ProvisioningConfigurationDto;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoGroupMembership;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoProvisionedUser;
use Passbolt\KeycloakSso\Service\Audit\GroupProvisioningAuditService;
use Passbolt\KeycloakSso\Service\Provisioning\KeycloakProvisioningApiService;
use Passbolt\KeycloakSso\Service\Provisioning\ProvisioningGroupSyncService;
use Passbolt\KeycloakSso\Test\Lib\KeycloakSsoIntegrationTestCase;
use Passbolt\KeycloakSso\Test\Utility\QueuedOidcHttpClient;
use RuntimeException;

final class ProvisioningGroupSyncServiceTest extends KeycloakSsoIntegrationTestCase
{
    private const ISSUER = 'https://keyclock.gobaz.ir/realms/passbolt';
    private const SUBJECT = 'e2bc1228-043a-4512-8a91-f08683e55e53';

    public function testDryRunCreatesNothing(): void
    {
        [$actor, $user] = $this->users(true);

        $counts = $this->service($actor, $this->responses())->run(true);

        $this->assertSame(1, $counts[ProvisioningGroupSyncService::OUTCOME_GROUP_WOULD_CREATE]);
        $this->assertSame(1, $counts[ProvisioningGroupSyncService::OUTCOME_MEMBERSHIP_WOULD_ADD]);
        $this->assertSame(0, TableRegistry::getTableLocator()->get('Groups')->find()->count());
        $this->assertSame(0, $this->mappedGroups()->find()->count());
        $this->assertSame(0, $this->memberships()->find()->count());
        $this->assertInstanceOf(User::class, $user);
    }

    public function testCreatesGroupAndAddsActiveUserAsNonManager(): void
    {
        [$actor, $user] = $this->users(true);

        $counts = $this->service($actor, $this->responses())->run();

        $this->assertSame(1, $counts[ProvisioningGroupSyncService::OUTCOME_GROUP_CREATED]);
        $this->assertSame(1, $counts[ProvisioningGroupSyncService::OUTCOME_MEMBERSHIP_ADDED]);
        $group = TableRegistry::getTableLocator()->get('Groups')->find()->where(['name' => 'Engineering'])->firstOrFail();
        $this->assertInstanceOf(Group::class, $group);
        $actorMembership = TableRegistry::getTableLocator()->get('GroupsUsers')->find()->where([
            'group_id' => $group->id,
            'user_id' => $actor->id,
        ])->firstOrFail();
        $userMembership = TableRegistry::getTableLocator()->get('GroupsUsers')->find()->where([
            'group_id' => $group->id,
            'user_id' => $user->id,
        ])->firstOrFail();
        $this->assertTrue($actorMembership->get('is_admin'));
        $this->assertFalse($userMembership->get('is_admin'));
        $this->assertSame(1, $this->mappedGroups()->find()->count());
        $state = $this->memberships()->find()->firstOrFail();
        $this->assertSame(KeycloakSsoGroupMembership::STATUS_ACTIVE, $state->get('status'));
    }

    public function testInactiveUserRemainsPendingThenIsAddedAfterActivation(): void
    {
        [$actor, $user] = $this->users(false);

        $first = $this->service($actor, $this->responses())->run();

        $this->assertSame(1, $first[ProvisioningGroupSyncService::OUTCOME_PENDING_ACTIVATION]);
        $this->assertSame(1, TableRegistry::getTableLocator()->get('GroupsUsers')->find()->count());
        $state = $this->memberships()->find()->firstOrFail();
        $this->assertSame(KeycloakSsoGroupMembership::STATUS_PENDING_ACTIVATION, $state->get('status'));

        TableRegistry::getTableLocator()->get('Users')->updateAll(['active' => true], ['id' => $user->id]);
        $second = $this->service($actor, $this->responses())->run();

        $this->assertSame(1, $second[ProvisioningGroupSyncService::OUTCOME_MEMBERSHIP_ADDED]);
        $this->assertSame(2, TableRegistry::getTableLocator()->get('GroupsUsers')->find()->count());
        $this->assertSame(
            KeycloakSsoGroupMembership::STATUS_ACTIVE,
            $this->memberships()->find()->firstOrFail()->get('status')
        );
    }

    public function testGroupWithSharedResourceRemainsPendingForClientCrypto(): void
    {
        [$actor, $user] = $this->users(false);
        $this->service($actor, $this->responses())->run();
        $group = TableRegistry::getTableLocator()->get('Groups')->find()->where(['name' => 'Engineering'])->firstOrFail();
        $this->assertInstanceOf(Group::class, $group);
        ResourceFactory::make()
            ->withSecretRevisions()
            ->withPermissionsFor([$group])
            ->withSecretsFor([$actor])
            ->persist();
        TableRegistry::getTableLocator()->get('Users')->updateAll(['active' => true], ['id' => $user->id]);

        $counts = $this->service($actor, $this->responses())->run();

        $this->assertSame(1, $counts[ProvisioningGroupSyncService::OUTCOME_PENDING_CRYPTO]);
        $this->assertSame(1, TableRegistry::getTableLocator()->get('GroupsUsers')->find()->count());
        $this->assertSame(
            KeycloakSsoGroupMembership::STATUS_PENDING_CRYPTO,
            $this->memberships()->find()->firstOrFail()->get('status')
        );
    }

    public function testDoesNotAdoptPassboltGroupByName(): void
    {
        [$actor] = $this->users(true);
        GroupFactory::make(['name' => 'Engineering'])->withGroupsManagersFor([$actor])->persist();

        $counts = $this->service($actor, $this->responses())->run();

        $this->assertSame(1, $counts[ProvisioningGroupSyncService::OUTCOME_FAILED]);
        $this->assertSame(0, $this->mappedGroups()->find()->count());
        $this->assertSame(1, TableRegistry::getTableLocator()->get('Groups')->find()->count());
    }

    public function testGroupSyncNeverTouchesProvisioningFromAnotherIssuer(): void
    {
        [$actor, $user] = $this->users(true);
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

        $this->service($actor, $this->responses())->run();

        $group = TableRegistry::getTableLocator()->get('Groups')->find()->where(['name' => 'Engineering'])
            ->firstOrFail();
        self::assertInstanceOf(Group::class, $group);
        $this->assertTrue(TableRegistry::getTableLocator()->get('GroupsUsers')->exists([
            'group_id' => $group->id,
            'user_id' => $user->id,
        ]));
        $this->assertFalse(TableRegistry::getTableLocator()->get('GroupsUsers')->exists([
            'group_id' => $group->id,
            'user_id' => $foreignUser->id,
        ]));
    }

    public function testAuthoritativeReconciliationRemovesOnlyManagedMissingMembership(): void
    {
        [$actor, $user] = $this->users(true);
        $this->service($actor, $this->responses(), true)->run();

        $counts = $this->service($actor, [
            ['access_token' => 'service-token', 'token_type' => 'Bearer'],
            [
                'id' => self::SUBJECT,
                'email' => 'new.user@example.test',
                'emailVerified' => true,
                'enabled' => true,
                'firstName' => 'New',
                'lastName' => 'User',
            ],
            [],
        ], true)->run();

        $this->assertSame(1, $counts[ProvisioningGroupSyncService::OUTCOME_MEMBERSHIP_REMOVED]);
        $this->assertFalse(TableRegistry::getTableLocator()->get('GroupsUsers')->exists(['user_id' => $user->id]));
        $state = $this->memberships()->find()->firstOrFail();
        $this->assertSame(KeycloakSsoGroupMembership::STATUS_REVOKED, $state->get('status'));
        $this->assertNotNull($state->get('revoked'));
        $this->assertTrue(TableRegistry::getTableLocator()->get('GroupsUsers')->exists(['user_id' => $actor->id]));
    }

    public function testAuthoritativeRemovalAppliesConfiguredResourceExpiryPolicy(): void
    {
        [$actor, $user] = $this->users(true);
        $this->service($actor, $this->responses(), true)->run();
        $group = TableRegistry::getTableLocator()->get('Groups')->find()->where(['name' => 'Engineering'])
            ->firstOrFail();
        self::assertInstanceOf(Group::class, $group);
        ResourceFactory::make()
            ->withSecretRevisions()
            ->withPermissionsFor([$group])
            ->withSecretsFor([$user])
            ->persist();
        $expiry = $this->createMock(ResourcesExpireResourcesServiceInterface::class);
        $expiry->expects($this->once())->method('expireResourcesForSecrets')->with(
            $this->callback(
                fn (array $secrets): bool => count($secrets) === 1 && array_values($secrets)[0] instanceof Secret
            )
        )->willReturn(true);

        $counts = $this->service($actor, [
            ['access_token' => 'service-token', 'token_type' => 'Bearer'],
            $this->responses()[1],
            [],
        ], true, $expiry)->run();

        $this->assertSame(1, $counts[ProvisioningGroupSyncService::OUTCOME_MEMBERSHIP_REMOVED]);
        $this->assertFalse(TableRegistry::getTableLocator()->get('GroupsUsers')->exists([
            'group_id' => $group->id,
            'user_id' => $user->id,
        ]));
    }

    public function testResourceExpiryFailureRollsBackAuthoritativeRemoval(): void
    {
        [$actor, $user] = $this->users(true);
        $this->service($actor, $this->responses(), true)->run();
        $group = TableRegistry::getTableLocator()->get('Groups')->find()->where(['name' => 'Engineering'])
            ->firstOrFail();
        self::assertInstanceOf(Group::class, $group);
        ResourceFactory::make()
            ->withSecretRevisions()
            ->withPermissionsFor([$group])
            ->withSecretsFor([$user])
            ->persist();
        $expiry = $this->createMock(ResourcesExpireResourcesServiceInterface::class);
        $expiry->expects($this->once())->method('expireResourcesForSecrets')
            ->willThrowException(new RuntimeException('expiry unavailable'));

        $counts = $this->service($actor, [
            ['access_token' => 'service-token', 'token_type' => 'Bearer'],
            $this->responses()[1],
            [],
        ], true, $expiry)->run();

        $this->assertSame(1, $counts[ProvisioningGroupSyncService::OUTCOME_FAILED]);
        $this->assertTrue(TableRegistry::getTableLocator()->get('GroupsUsers')->exists([
            'group_id' => $group->id,
            'user_id' => $user->id,
        ]));
        $this->assertSame(
            KeycloakSsoGroupMembership::STATUS_ACTIVE,
            $this->memberships()->find()->firstOrFail()->get('status')
        );
    }

    public function testProviderFailureNeverRemovesManagedMembership(): void
    {
        [$actor, $user] = $this->users(true);
        $this->service($actor, $this->responses(), true)->run();

        $counts = $this->service($actor, [
            ['access_token' => 'service-token', 'token_type' => 'Bearer'],
            [
                'id' => self::SUBJECT,
                'email' => 'new.user@example.test',
                'emailVerified' => true,
                'enabled' => true,
                'firstName' => 'New',
                'lastName' => 'User',
            ],
            new OidcNetworkException('provider unavailable'),
        ], true)->run();

        $this->assertSame(1, $counts[ProvisioningGroupSyncService::OUTCOME_FAILED]);
        $this->assertTrue(TableRegistry::getTableLocator()->get('GroupsUsers')->exists(['user_id' => $user->id]));
        $this->assertSame(
            KeycloakSsoGroupMembership::STATUS_ACTIVE,
            $this->memberships()->find()->firstOrFail()->get('status')
        );
    }

    public function testPreviouslyManagedMembershipCannotDriftBackWhileAbsentFromKeycloak(): void
    {
        [$actor, $user] = $this->users(true);
        $this->service($actor, $this->responses(), true)->run();
        $absentResponses = [
            ['access_token' => 'service-token', 'token_type' => 'Bearer'],
            [
                'id' => self::SUBJECT,
                'email' => 'new.user@example.test',
                'emailVerified' => true,
                'enabled' => true,
                'firstName' => 'New',
                'lastName' => 'User',
            ],
            [],
        ];
        $this->service($actor, $absentResponses, true)->run();
        $group = TableRegistry::getTableLocator()->get('Groups')->find()->where(['name' => 'Engineering'])
            ->firstOrFail();
        self::assertInstanceOf(Group::class, $group);
        (new GroupsUsersAddService())->add(new UserAccessControl(Role::ADMIN, $actor->id), [
            'group_id' => $group->id,
            'user_id' => $user->id,
            'is_admin' => false,
        ]);

        $counts = $this->service($actor, $absentResponses, true)->run();

        $this->assertSame(1, $counts[ProvisioningGroupSyncService::OUTCOME_MEMBERSHIP_REMOVED]);
        $this->assertFalse(TableRegistry::getTableLocator()->get('GroupsUsers')->exists([
            'group_id' => $group->id,
            'user_id' => $user->id,
        ]));
        $this->assertSame(
            KeycloakSsoGroupMembership::STATUS_REVOKED,
            $this->memberships()->find()->firstOrFail()->get('status')
        );
    }

    /** @return array{0: User, 1: User} */
    private function users(bool $active): array
    {
        $actor = UserFactory::make()->admin()->active()->notDisabled()->persist();
        $factory = UserFactory::make(['username' => 'new.user@example.test'])->user()->notDisabled();
        $user = ($active ? $factory->active() : $factory->inactive())->persist();
        $this->assertInstanceOf(User::class, $actor);
        $this->assertInstanceOf(User::class, $user);
        $provisioned = $this->provisionedUsers()->newEntity([
            'id' => UuidFactory::uuid(),
            'user_id' => $user->id,
            'issuer' => self::ISSUER,
            'subject' => self::SUBJECT,
            'email_at_provisioning' => 'new.user@example.test',
            'source_event_id' => UuidFactory::uuid(),
            'lifecycle_status' => KeycloakSsoProvisionedUser::STATUS_ACTIVE,
        ], ['accessibleFields' => ['*' => true]]);
        $this->provisionedUsers()->saveOrFail($provisioned);

        return [$actor, $user];
    }

    /** @return list<array<mixed>> */
    private function responses(): array
    {
        return [
            ['access_token' => 'service-token', 'token_type' => 'Bearer'],
            [
                'id' => self::SUBJECT,
                'email' => 'new.user@example.test',
                'emailVerified' => true,
                'enabled' => true,
                'firstName' => 'New',
                'lastName' => 'User',
            ],
            [['id' => 'engineering-id', 'name' => 'Engineering', 'path' => '/Engineering']],
        ];
    }

    private function service(
        User $actor,
        array $responses,
        bool $reconciliationEnabled = false,
        ?ResourcesExpireResourcesServiceInterface $resourcesExpiry = null,
    ): ProvisioningGroupSyncService {
        $configuration = new ProvisioningConfigurationDto(
            self::ISSUER,
            'https://keyclock.gobaz.ir/admin/realms/passbolt',
            'passbolt-provisioning',
            'provisioning-secret',
            $actor->id,
            86_400,
            300,
            100
        );
        $api = new KeycloakProvisioningApiService(
            $configuration,
            new OidcDiscoveryDocument(
                self::ISSUER,
                self::ISSUER . '/protocol/openid-connect/auth',
                self::ISSUER . '/protocol/openid-connect/token',
                self::ISSUER . '/protocol/openid-connect/certs'
            ),
            new QueuedOidcHttpClient($responses)
        );

        return new ProvisioningGroupSyncService(
            $configuration,
            $api,
            $resourcesExpiry ?? new ResourcesExpireResourcesFallbackServiceService(),
            new GroupProvisioningAuditService(),
            $reconciliationEnabled
        );
    }

    private function provisionedUsers(): Table
    {
        return TableRegistry::getTableLocator()->get('Passbolt/KeycloakSso.KeycloakSsoProvisionedUsers');
    }

    private function mappedGroups(): Table
    {
        return TableRegistry::getTableLocator()->get('Passbolt/KeycloakSso.KeycloakSsoProvisionedGroups');
    }

    private function memberships(): Table
    {
        return TableRegistry::getTableLocator()->get('Passbolt/KeycloakSso.KeycloakSsoGroupMemberships');
    }
}
