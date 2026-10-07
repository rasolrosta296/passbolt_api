<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Model;

use App\Model\Entity\Group;
use App\Model\Entity\User;
use App\Test\Factory\GroupFactory;
use App\Test\Factory\UserFactory;
use App\Utility\UuidFactory;
use Cake\Database\Exception\QueryException;
use Cake\Datasource\Exception\RecordNotFoundException;
use Cake\ORM\TableRegistry;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoGroupMembership;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoProvisionedGroup;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoProvisionedUser;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoProvisioningEvent;
use Passbolt\KeycloakSso\Test\Lib\KeycloakSsoIntegrationTestCase;

final class ProvisioningPersistenceTest extends KeycloakSsoIntegrationTestCase
{
    public function testDatabaseConstraintRejectsDuplicateProviderEventWithoutApplicationRules(): void
    {
        $table = TableRegistry::getTableLocator()->get('Passbolt/KeycloakSso.KeycloakSsoProvisioningEvents');
        $data = [
            'id' => UuidFactory::uuid(),
            'event_id' => '8d020e76-4951-58d2-b68e-99e2fc1053f8',
            'issuer' => 'https://keyclock.gobaz.ir/realms/passbolt',
            'subject' => 'e2bc1228-043a-4512-8a91-f08683e55e53',
            'event_time' => 1_789_569_606_000,
            'operation' => 'CREATE',
            'status' => KeycloakSsoProvisioningEvent::STATUS_PENDING,
        ];

        $first = $table->newEntity($data, ['accessibleFields' => ['*' => true]]);
        $this->assertNotFalse($table->saveOrFail($first));
        $now = date('Y-m-d H:i:s');
        $this->expectException(QueryException::class);
        $table->getConnection()->insert($table->getTable(), [
            'id' => UuidFactory::uuid(),
            'event_id' => $data['event_id'],
            'issuer' => $data['issuer'],
            'subject' => $data['subject'],
            'event_time' => $data['event_time'],
            'operation' => $data['operation'],
            'status' => $data['status'],
            'user_id' => null,
            'failure_code' => null,
            'created' => $now,
            'modified' => $now,
        ]);
    }

    public function testDatabaseRejectsDuplicateProvisionedSubjectAndUser(): void
    {
        $user = UserFactory::make()->user()->persist();
        $otherUser = UserFactory::make()->user()->persist();
        $this->assertInstanceOf(User::class, $user);
        $this->assertInstanceOf(User::class, $otherUser);
        $table = TableRegistry::getTableLocator()->get('Passbolt/KeycloakSso.KeycloakSsoProvisionedUsers');
        $base = [
            'issuer' => 'https://keyclock.gobaz.ir/realms/passbolt',
            'subject' => 'e2bc1228-043a-4512-8a91-f08683e55e53',
            'email_at_provisioning' => 'provisioned@example.test',
            'source_event_id' => '8d020e76-4951-58d2-b68e-99e2fc1053f8',
            'lifecycle_status' => KeycloakSsoProvisionedUser::STATUS_ACTIVE,
        ];
        $first = $table->newEntity(
            ['id' => UuidFactory::uuid(), 'user_id' => $user->id] + $base,
            ['accessibleFields' => ['*' => true]]
        );
        $table->saveOrFail($first);

        $duplicateSubject = $table->newEntity([
            'id' => UuidFactory::uuid(),
            'user_id' => $otherUser->id,
            'source_event_id' => '7cd5488d-b1ec-42f6-925d-795620ff2701',
        ] + $base, ['accessibleFields' => ['*' => true]]);
        $this->assertFalse($table->save($duplicateSubject));

        $duplicateUser = $table->newEntity([
            'id' => UuidFactory::uuid(),
            'user_id' => $user->id,
            'subject' => '53a9a0c1-8ce8-4cbc-9b38-04938fea2311',
            'source_event_id' => '4d2d5c43-a76a-5d4a-8f47-2b1f0268e3d6',
        ] + $base, ['accessibleFields' => ['*' => true]]);
        $this->assertFalse($table->save($duplicateUser));
    }

    public function testProvisioningRecordsDoNotCreateIdentityLink(): void
    {
        $this->expectException(RecordNotFoundException::class);

        TableRegistry::getTableLocator()
            ->get('Passbolt/KeycloakSso.KeycloakSsoIdentities')
            ->find()
            ->firstOrFail();
    }

    public function testDatabaseRejectsDuplicateProviderGroupAndMembership(): void
    {
        $actor = UserFactory::make()->admin()->active()->notDisabled()->persist();
        $user = UserFactory::make()->user()->active()->notDisabled()->persist();
        $group = GroupFactory::make()->withGroupsManagersFor([$actor])->persist();
        $otherGroup = GroupFactory::make()->withGroupsManagersFor([$actor])->persist();
        $this->assertInstanceOf(User::class, $user);
        $this->assertInstanceOf(Group::class, $group);
        $this->assertInstanceOf(Group::class, $otherGroup);
        $groups = TableRegistry::getTableLocator()->get('Passbolt/KeycloakSso.KeycloakSsoProvisionedGroups');
        $mapping = $groups->newEntity([
            'id' => UuidFactory::uuid(),
            'group_id' => $group->id,
            'issuer' => 'https://keyclock.gobaz.ir/realms/passbolt',
            'keycloak_group_id' => 'engineering-id',
            'keycloak_group_path' => '/Engineering',
        ], ['accessibleFields' => ['*' => true]]);
        $this->assertInstanceOf(KeycloakSsoProvisionedGroup::class, $mapping);
        $groups->saveOrFail($mapping);
        $duplicate = $groups->newEntity([
            'id' => UuidFactory::uuid(),
            'group_id' => $otherGroup->id,
            'issuer' => 'https://keyclock.gobaz.ir/realms/passbolt',
            'keycloak_group_id' => 'engineering-id',
            'keycloak_group_path' => '/Engineering',
        ], ['accessibleFields' => ['*' => true]]);
        $this->assertFalse($groups->save($duplicate));

        $memberships = TableRegistry::getTableLocator()->get(
            'Passbolt/KeycloakSso.KeycloakSsoGroupMemberships'
        );
        $first = $memberships->newEntity([
            'id' => UuidFactory::uuid(),
            'provisioned_group_id' => $mapping->id,
            'user_id' => $user->id,
            'status' => KeycloakSsoGroupMembership::STATUS_PENDING_ACTIVATION,
        ], ['accessibleFields' => ['*' => true]]);
        $memberships->saveOrFail($first);
        $duplicateMembership = $memberships->newEntity([
            'id' => UuidFactory::uuid(),
            'provisioned_group_id' => $mapping->id,
            'user_id' => $user->id,
            'status' => KeycloakSsoGroupMembership::STATUS_PENDING_CRYPTO,
        ], ['accessibleFields' => ['*' => true]]);
        $this->assertFalse($memberships->save($duplicateMembership));
    }

    public function testDatabaseConstraintRejectsDuplicateProviderGroupWithoutApplicationRules(): void
    {
        $actor = UserFactory::make()->admin()->active()->notDisabled()->persist();
        $group = GroupFactory::make()->withGroupsManagersFor([$actor])->persist();
        $otherGroup = GroupFactory::make()->withGroupsManagersFor([$actor])->persist();
        $this->assertInstanceOf(Group::class, $group);
        $this->assertInstanceOf(Group::class, $otherGroup);
        $table = TableRegistry::getTableLocator()->get('Passbolt/KeycloakSso.KeycloakSsoProvisionedGroups');
        $issuer = 'https://keyclock.gobaz.ir/realms/passbolt';
        $providerGroupId = 'engineering-id';
        $mapping = $table->newEntity([
            'id' => UuidFactory::uuid(),
            'group_id' => $group->id,
            'issuer' => $issuer,
            'keycloak_group_id' => $providerGroupId,
            'keycloak_group_path' => '/Engineering',
        ], ['accessibleFields' => ['*' => true]]);
        $table->saveOrFail($mapping);

        $now = date('Y-m-d H:i:s');
        $this->expectException(QueryException::class);
        $table->getConnection()->insert($table->getTable(), [
            'id' => UuidFactory::uuid(),
            'group_id' => $otherGroup->id,
            'issuer' => $issuer,
            'keycloak_group_id' => $providerGroupId,
            'keycloak_group_path' => '/Engineering',
            'created' => $now,
            'modified' => $now,
        ]);
    }

    public function testDatabaseConstraintRejectsDuplicateGroupMembershipWithoutApplicationRules(): void
    {
        $actor = UserFactory::make()->admin()->active()->notDisabled()->persist();
        $user = UserFactory::make()->user()->active()->notDisabled()->persist();
        $group = GroupFactory::make()->withGroupsManagersFor([$actor])->persist();
        $this->assertInstanceOf(User::class, $user);
        $this->assertInstanceOf(Group::class, $group);
        $groups = TableRegistry::getTableLocator()->get('Passbolt/KeycloakSso.KeycloakSsoProvisionedGroups');
        $mapping = $groups->newEntity([
            'id' => UuidFactory::uuid(),
            'group_id' => $group->id,
            'issuer' => 'https://keyclock.gobaz.ir/realms/passbolt',
            'keycloak_group_id' => 'engineering-id',
            'keycloak_group_path' => '/Engineering',
        ], ['accessibleFields' => ['*' => true]]);
        $this->assertInstanceOf(KeycloakSsoProvisionedGroup::class, $mapping);
        $groups->saveOrFail($mapping);
        $memberships = TableRegistry::getTableLocator()->get(
            'Passbolt/KeycloakSso.KeycloakSsoGroupMemberships'
        );
        $first = $memberships->newEntity([
            'id' => UuidFactory::uuid(),
            'provisioned_group_id' => $mapping->id,
            'user_id' => $user->id,
            'status' => KeycloakSsoGroupMembership::STATUS_PENDING_ACTIVATION,
        ], ['accessibleFields' => ['*' => true]]);
        $memberships->saveOrFail($first);

        $now = date('Y-m-d H:i:s');
        $this->expectException(QueryException::class);
        $memberships->getConnection()->insert($memberships->getTable(), [
            'id' => UuidFactory::uuid(),
            'provisioned_group_id' => $mapping->id,
            'user_id' => $user->id,
            'status' => KeycloakSsoGroupMembership::STATUS_PENDING_CRYPTO,
            'failure_code' => null,
            'created' => $now,
            'modified' => $now,
        ]);
    }
}
