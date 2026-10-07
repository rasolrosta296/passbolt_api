<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Provisioning;

use App\Model\Entity\Group;
use App\Model\Entity\GroupsUser;
use App\Model\Entity\Role;
use App\Model\Entity\Secret;
use App\Model\Entity\User;
use App\Model\Table\GroupsTable;
use App\Model\Table\GroupsUsersTable;
use App\Model\Table\PermissionsTable;
use App\Service\GroupsUsers\GroupsUsersAddService;
use App\Service\GroupsUsers\GroupsUsersDeleteService;
use App\Service\Resources\ResourcesExpireResourcesServiceInterface;
use App\Utility\UserAccessControl;
use App\Utility\UuidFactory;
use Cake\Datasource\ConnectionManager;
use Cake\I18n\DateTime;
use Cake\ORM\Locator\LocatorAwareTrait;
use Cake\ORM\Table;
use Passbolt\KeycloakSso\Error\Exception\ProvisioningException;
use Passbolt\KeycloakSso\Model\Dto\KeycloakProvisioningGroupDto;
use Passbolt\KeycloakSso\Model\Dto\ProvisioningConfigurationDto;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoGroupMembership;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoProvisionedGroup;
use Passbolt\KeycloakSso\Service\Audit\GroupProvisioningAuditService;
use Throwable;

final class ProvisioningGroupSyncService
{
    use LocatorAwareTrait;

    public const OUTCOME_GROUP_CREATED = 'groups_created';
    public const OUTCOME_GROUP_WOULD_CREATE = 'groups_would_create';
    public const OUTCOME_MEMBERSHIP_ADDED = 'memberships_added';
    public const OUTCOME_MEMBERSHIP_WOULD_ADD = 'memberships_would_add';
    public const OUTCOME_PENDING_ACTIVATION = 'pending_activation';
    public const OUTCOME_PENDING_CRYPTO = 'pending_crypto';
    public const OUTCOME_EXISTING = 'existing';
    public const OUTCOME_MEMBERSHIP_REMOVED = 'memberships_removed';
    public const OUTCOME_MEMBERSHIP_WOULD_REMOVE = 'memberships_would_remove';
    public const OUTCOME_SKIPPED = 'skipped';
    public const OUTCOME_FAILED = 'failed';

    private const MAX_USER_PAGES = 1_000;

    /** Construct the isolated Keycloak-group synchronization service. */
    public function __construct(
        private readonly ProvisioningConfigurationDto $configuration,
        private readonly KeycloakProvisioningApiService $api,
        private readonly ResourcesExpireResourcesServiceInterface $resourcesExpiry,
        private readonly GroupProvisioningAuditService $audit = new GroupProvisioningAuditService(),
        private readonly bool $reconciliationEnabled = false,
    ) {
    }

    /**
     * Synchronize mapped groups and cryptographically safe memberships.
     *
     * @return array<string, int>
     */
    public function run(bool $dryRun = false): array
    {
        $counts = array_fill_keys([
            self::OUTCOME_GROUP_CREATED,
            self::OUTCOME_GROUP_WOULD_CREATE,
            self::OUTCOME_MEMBERSHIP_ADDED,
            self::OUTCOME_MEMBERSHIP_WOULD_ADD,
            self::OUTCOME_PENDING_ACTIVATION,
            self::OUTCOME_PENDING_CRYPTO,
            self::OUTCOME_EXISTING,
            self::OUTCOME_MEMBERSHIP_REMOVED,
            self::OUTCOME_MEMBERSHIP_WOULD_REMOVE,
            self::OUTCOME_SKIPPED,
            self::OUTCOME_FAILED,
        ], 0);
        $actor = $this->activeAdminActor();
        $first = 0;
        for ($page = 0; $page < self::MAX_USER_PAGES; $page++) {
            $provisionedUsers = $this->provisionedUsersTable()->find()
                ->contain(['Users'])
                ->where(['KeycloakSsoProvisionedUsers.issuer' => $this->configuration->issuer])
                ->orderByAsc('KeycloakSsoProvisionedUsers.id')
                ->limit($this->configuration->batchSize)
                ->offset($first)
                ->all();
            $received = $provisionedUsers->count();
            foreach ($provisionedUsers as $provisionedUser) {
                $user = $provisionedUser->get('user');
                if (!($user instanceof User) || $user->isDeleted() || $user->isDisabled()) {
                    $counts[self::OUTCOME_SKIPPED]++;
                    continue;
                }
                try {
                    $keycloakUser = $this->api->user((string)$provisionedUser->get('subject'));
                    if (!$keycloakUser->enabled || !$keycloakUser->emailVerified) {
                        $counts[self::OUTCOME_SKIPPED]++;
                        continue;
                    }
                    $seen = [];
                    foreach ($this->api->userGroups($keycloakUser->subject) as $keycloakGroup) {
                        if (isset($seen[$keycloakGroup->id])) {
                            throw new ProvisioningException('duplicate_keycloak_group');
                        }
                        $seen[$keycloakGroup->id] = true;
                        $mapping = $this->findMapping($keycloakGroup);
                        if ($mapping === null) {
                            $counts[$dryRun
                                ? self::OUTCOME_GROUP_WOULD_CREATE
                                : self::OUTCOME_GROUP_CREATED]++;
                            if (!$dryRun) {
                                $mapping = $this->createMapping($keycloakGroup, $actor);
                                $this->audit->record('group_created', 'none', null, (string)$mapping->get('group_id'));
                            }
                        }
                        if ($dryRun && $mapping === null) {
                            $counts[$user->isActive()
                                ? self::OUTCOME_MEMBERSHIP_WOULD_ADD
                                : self::OUTCOME_PENDING_ACTIVATION]++;
                            continue;
                        }
                        if (!($mapping instanceof KeycloakSsoProvisionedGroup)) {
                            throw new ProvisioningException('group_mapping_unavailable');
                        }
                        $outcome = $this->synchronizeMembership($mapping, $user, $actor, $dryRun);
                        $counts[$outcome]++;
                    }
                    if ($this->reconciliationEnabled) {
                        foreach ($this->reconcileRemovedMemberships($user, $actor, $seen, $dryRun) as $outcome) {
                            $counts[$outcome]++;
                        }
                    }
                } catch (Throwable) {
                    $this->audit->record('failed', 'unexpected', $user->id);
                    $counts[self::OUTCOME_FAILED]++;
                }
            }
            if ($received < $this->configuration->batchSize) {
                return $counts;
            }
            $first += $received;
        }

        throw new ProvisioningException('The provisioned user collection exceeded the page limit.');
    }

    /**
     * Remove only plugin-managed memberships absent from a complete Keycloak response.
     *
     * @param array<string, true> $seen
     * @return list<string>
     */
    private function reconcileRemovedMemberships(User $user, User $actor, array $seen, bool $dryRun): array
    {
        $managed = $this->groupMembershipsTable()->find()
            ->where([
                'KeycloakSsoGroupMemberships.user_id' => $user->id,
            ])
            ->contain(['ProvisionedGroups'])
            ->orderByAsc('KeycloakSsoGroupMemberships.id')
            ->all();
        $outcomes = [];
        foreach ($managed as $membership) {
            $mapping = $membership->get('provisioned_group');
            if (
                !($mapping instanceof KeycloakSsoProvisionedGroup) ||
                !hash_equals($this->configuration->issuer, (string)$mapping->get('issuer')) ||
                isset($seen[(string)$mapping->get('keycloak_group_id')])
            ) {
                continue;
            }
            $groupId = (string)$mapping->get('group_id');
            $groupUser = $this->groupsUsersTable()->find()->where([
                'group_id' => $groupId,
                'user_id' => $user->id,
            ])->first();
            if (
                !($groupUser instanceof GroupsUser) &&
                $membership->get('status') === KeycloakSsoGroupMembership::STATUS_REVOKED
            ) {
                continue;
            }
            if ($dryRun) {
                $outcomes[] = self::OUTCOME_MEMBERSHIP_WOULD_REMOVE;
                continue;
            }
            $this->groupsUsersTable()->getConnection()->transactional(function () use (
                $groupUser,
                $actor,
                $membership
            ): void {
                if ($groupUser instanceof GroupsUser) {
                    $changes = (new GroupsUsersDeleteService())->delete(
                        new UserAccessControl(Role::ADMIN, $actor->id),
                        (string)$groupUser->get('id')
                    );
                    $this->resourcesExpiry->expireResourcesForSecrets(
                        $changes->getDeletedEntities(Secret::class)
                    );
                }
                $membership->set('status', KeycloakSsoGroupMembership::STATUS_REVOKED);
                $membership->set('failure_code', null);
                $membership->set('revoked', DateTime::now());
                $this->groupMembershipsTable()->saveOrFail($membership);
            });
            $this->audit->record('membership_removed', 'none', $user->id, $groupId);
            $outcomes[] = self::OUTCOME_MEMBERSHIP_REMOVED;
        }

        return $outcomes;
    }

    /** Locate an immutable provider-group mapping and validate its Passbolt group. */
    private function findMapping(KeycloakProvisioningGroupDto $keycloakGroup): ?KeycloakSsoProvisionedGroup
    {
        $mapping = $this->provisionedGroupsTable()->find()->where([
            'issuer' => $this->configuration->issuer,
            'keycloak_group_id' => $keycloakGroup->id,
        ])->contain(['Groups'])->first();
        if ($mapping === null) {
            return null;
        }
        if (!($mapping instanceof KeycloakSsoProvisionedGroup)) {
            throw new ProvisioningException('group_mapping_unavailable');
        }
        $group = $mapping->get('group');
        if (!($group instanceof Group) || $group->deleted) {
            throw new ProvisioningException('mapped_group_unavailable');
        }

        return $mapping;
    }

    /** Atomically create a Passbolt group and its immutable Keycloak mapping. */
    private function createMapping(
        KeycloakProvisioningGroupDto $keycloakGroup,
        User $actor
    ): KeycloakSsoProvisionedGroup {
        /** @var \Cake\Database\Connection $connection */
        $connection = ConnectionManager::get('default');

        return $connection->transactional(function () use ($keycloakGroup, $actor): KeycloakSsoProvisionedGroup {
            $existing = $this->findMapping($keycloakGroup);
            if ($existing !== null) {
                return $existing;
            }
            $name = $keycloakGroup->passboltName();
            if ($this->groupsTable()->find()->where(['name' => $name, 'deleted' => false])->count() > 0) {
                throw new ProvisioningException('group_name_collision');
            }
            $group = $this->groupsTable()->create([
                'name' => $name,
                'groups_users' => [[
                    'user_id' => $actor->id,
                    'is_admin' => true,
                ]],
            ], new UserAccessControl(Role::ADMIN, $actor->id));
            $mapping = $this->provisionedGroupsTable()->newEntity([
                'id' => UuidFactory::uuid(),
                'group_id' => $group->id,
                'issuer' => $this->configuration->issuer,
                'keycloak_group_id' => $keycloakGroup->id,
                'keycloak_group_path' => $keycloakGroup->path,
            ], ['accessibleFields' => ['*' => true]]);
            $this->provisionedGroupsTable()->saveOrFail($mapping);

            return $mapping;
        });
    }

    /** Apply one membership only when no client-side secret encryption is required. */
    private function synchronizeMembership(
        KeycloakSsoProvisionedGroup $mapping,
        User $user,
        User $actor,
        bool $dryRun
    ): string {
        $groupId = (string)$mapping->get('group_id');
        $existing = $this->groupsUsersTable()->find()->where([
            'group_id' => $groupId,
            'user_id' => $user->id,
        ])->first();
        if ($existing instanceof GroupsUser) {
            if (!$dryRun) {
                $this->saveMembershipState($mapping->id, $user->id, KeycloakSsoGroupMembership::STATUS_ACTIVE);
            }

            return self::OUTCOME_EXISTING;
        }
        if (!$user->isActive()) {
            if (!$dryRun) {
                $this->saveMembershipState(
                    $mapping->id,
                    $user->id,
                    KeycloakSsoGroupMembership::STATUS_PENDING_ACTIVATION
                );
                $this->audit->record('membership_pending', 'activation', $user->id, $groupId);
            }

            return self::OUTCOME_PENDING_ACTIVATION;
        }
        $missingSecrets = $this->permissionsTable()
            ->findAcosAccessesDiffBetweenGroupAndUser(PermissionsTable::RESOURCE_ACO, $groupId, $user->id)
            ->limit(1)
            ->count();
        if ($missingSecrets > 0) {
            if (!$dryRun) {
                $this->saveMembershipState(
                    $mapping->id,
                    $user->id,
                    KeycloakSsoGroupMembership::STATUS_PENDING_CRYPTO
                );
                $this->audit->record('membership_pending', 'client_crypto', $user->id, $groupId);
            }

            return self::OUTCOME_PENDING_CRYPTO;
        }
        if ($dryRun) {
            return self::OUTCOME_MEMBERSHIP_WOULD_ADD;
        }

        /** @var \Cake\Database\Connection $connection */
        $connection = ConnectionManager::get('default');
        $connection->transactional(function () use ($actor, $groupId, $mapping, $user): void {
            (new GroupsUsersAddService())->add(new UserAccessControl(Role::ADMIN, $actor->id), [
                'group_id' => $groupId,
                'user_id' => $user->id,
                'is_admin' => false,
            ]);
            $this->saveMembershipState($mapping->id, $user->id, KeycloakSsoGroupMembership::STATUS_ACTIVE);
        });
        $this->audit->record('membership_added', 'none', $user->id, $groupId);

        return self::OUTCOME_MEMBERSHIP_ADDED;
    }

    /** Upsert one non-secret desired membership state. */
    private function saveMembershipState(string $mappingId, string $userId, string $status): void
    {
        $table = $this->groupMembershipsTable();
        $entity = $table->find()->where([
            'provisioned_group_id' => $mappingId,
            'user_id' => $userId,
        ])->first();
        if ($entity === null) {
            $entity = $table->newEntity([
                'id' => UuidFactory::uuid(),
                'provisioned_group_id' => $mappingId,
                'user_id' => $userId,
                'status' => $status,
                'failure_code' => null,
            ], ['accessibleFields' => ['*' => true]]);
        } else {
            $entity->set('status', $status);
            $entity->set('failure_code', null);
        }
        $entity->set('revoked', null);
        $table->saveOrFail($entity);
    }

    /** Load and validate the configured Passbolt administrator. */
    private function activeAdminActor(): User
    {
        $users = $this->fetchTable('Users');
        $actor = $users->find()->where(['Users.id' => $this->configuration->actorUserId])->first();
        /** @var \App\Model\Table\RolesTable $roles */
        $roles = $this->fetchTable('Roles');
        $adminRoleId = $roles->getIdByName(Role::ADMIN);
        if (
            !($actor instanceof User) || !$actor->isActive() || $actor->isDeleted() ||
            $actor->isDisabled() || !hash_equals($adminRoleId, $actor->role_id)
        ) {
            throw new ProvisioningException('actor_unavailable');
        }

        return $actor;
    }

    /** @return \Passbolt\KeycloakSso\Model\Table\KeycloakSsoProvisionedUsersTable */
    private function provisionedUsersTable(): Table
    {
        return $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoProvisionedUsers');
    }

    /** @return \Passbolt\KeycloakSso\Model\Table\KeycloakSsoProvisionedGroupsTable */
    private function provisionedGroupsTable(): Table
    {
        return $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoProvisionedGroups');
    }

    /** @return \Passbolt\KeycloakSso\Model\Table\KeycloakSsoGroupMembershipsTable */
    private function groupMembershipsTable(): Table
    {
        return $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoGroupMemberships');
    }

    /** Return the core Passbolt groups table. */
    private function groupsTable(): GroupsTable
    {
        /** @var \App\Model\Table\GroupsTable $table */
        $table = $this->fetchTable('Groups');

        return $table;
    }

    /** Return the core Passbolt group memberships table. */
    private function groupsUsersTable(): GroupsUsersTable
    {
        /** @var \App\Model\Table\GroupsUsersTable $table */
        $table = $this->fetchTable('GroupsUsers');

        return $table;
    }

    /** Return the core Passbolt permissions table. */
    private function permissionsTable(): PermissionsTable
    {
        /** @var \App\Model\Table\PermissionsTable $table */
        $table = $this->fetchTable('Permissions');

        return $table;
    }
}
