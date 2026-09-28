<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Provisioning;

use App\Model\Entity\Group;
use App\Model\Entity\GroupsUser;
use App\Model\Entity\User;
use App\Model\Table\GroupsUsersTable;
use Cake\Datasource\ConnectionManager;
use Cake\Http\Exception\BadRequestException;
use Cake\Http\Exception\ForbiddenException;
use Cake\ORM\Locator\LocatorAwareTrait;
use Cake\ORM\Table;
use Cake\Validation\Validation;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoGroupMembership;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoProvisionedGroup;
use Passbolt\KeycloakSso\Service\Audit\GroupProvisioningAuditService;

final class GroupProvisioningQueueService
{
    use LocatorAwareTrait;

    private const MAX_PENDING_RESULTS = 100;
    private const MAX_PENDING_PAGES = 1_000;

    /** Construct the manager-only pending membership queue. */
    public function __construct(
        private readonly GroupProvisioningAuditService $audit = new GroupProvisioningAuditService(),
    ) {
    }

    /**
     * Return pending cryptographic memberships managed by the authenticated user.
     *
     * @return list<array{id: string, group_id: string, user_id: string}>
     */
    public function pendingForManager(string $managerId): array
    {
        $this->assertUuid($managerId);
        $result = [];
        $offset = 0;
        for ($page = 0; $page < self::MAX_PENDING_PAGES; $page++) {
            $pending = $this->membershipsTable()->find()->where([
                'KeycloakSsoGroupMemberships.status' => KeycloakSsoGroupMembership::STATUS_PENDING_CRYPTO,
            ])
                ->innerJoin(
                    ['MappedGroupsFilter' => 'keycloak_sso_provisioned_groups'],
                    ['MappedGroupsFilter.id = KeycloakSsoGroupMemberships.provisioned_group_id']
                )
                ->innerJoin(
                    ['ManagerMembershipsFilter' => 'groups_users'],
                    [
                        'ManagerMembershipsFilter.group_id = MappedGroupsFilter.group_id',
                        'ManagerMembershipsFilter.user_id' => $managerId,
                        'ManagerMembershipsFilter.is_admin' => true,
                    ]
                )
                ->contain(['ProvisionedGroups.Groups', 'Users'])
                ->orderByAsc('KeycloakSsoGroupMemberships.created')
                ->limit(self::MAX_PENDING_RESULTS)
                ->offset($offset)
                ->all();
            $received = $pending->count();
            foreach ($pending as $membership) {
                $mapping = $membership->get('provisioned_group');
                $user = $membership->get('user');
                if (!($mapping instanceof KeycloakSsoProvisionedGroup) || !($user instanceof User)) {
                    continue;
                }
                $group = $mapping->get('group');
                if (
                    !($group instanceof Group) || $group->deleted || !$user->isActive() ||
                    $user->isDeleted() || $user->isDisabled() ||
                    !$this->groupsUsersTable()->isManager($managerId, (string)$mapping->get('group_id'))
                ) {
                    continue;
                }
                $result[] = [
                    'id' => (string)$membership->get('id'),
                    'group_id' => (string)$mapping->get('group_id'),
                    'user_id' => (string)$membership->get('user_id'),
                ];
                if (count($result) === self::MAX_PENDING_RESULTS) {
                    return $result;
                }
            }
            if ($received < self::MAX_PENDING_RESULTS) {
                return $result;
            }
            $offset += $received;
        }

        return $result;
    }

    /**
     * Mark a queue item complete only after the normal Passbolt group update exists.
     */
    public function complete(string $membershipId, string $managerId): void
    {
        $this->assertUuid($membershipId);
        $this->assertUuid($managerId);
        /** @var \Cake\Database\Connection $connection */
        $connection = ConnectionManager::get('default');
        $completed = $connection->transactional(function () use ($membershipId, $managerId): array {
            $membership = $this->membershipsTable()->find()->where([
                'KeycloakSsoGroupMemberships.id' => $membershipId,
            ])->contain(['ProvisionedGroups.Groups', 'Users'])->epilog('FOR UPDATE')->first();
            if (!($membership instanceof KeycloakSsoGroupMembership)) {
                throw new BadRequestException(__('The group-provisioning request is unavailable.'));
            }
            $mapping = $membership->get('provisioned_group');
            if (!($mapping instanceof KeycloakSsoProvisionedGroup)) {
                throw new BadRequestException(__('The group-provisioning request is unavailable.'));
            }
            $group = $mapping->get('group');
            $user = $membership->get('user');
            if (
                !($group instanceof Group) || $group->deleted ||
                !($user instanceof User) || !$user->isActive() || $user->isDeleted() || $user->isDisabled()
            ) {
                throw new BadRequestException(__('The group-provisioning request is unavailable.'));
            }
            $groupId = (string)$mapping->get('group_id');
            $userId = (string)$membership->get('user_id');
            if (!$this->groupsUsersTable()->isManager($managerId, $groupId)) {
                throw new ForbiddenException(__('You are not authorized to complete this group-provisioning request.'));
            }
            if ($membership->get('status') === KeycloakSsoGroupMembership::STATUS_ACTIVE) {
                return [$userId, $groupId, false];
            }
            if ($membership->get('status') !== KeycloakSsoGroupMembership::STATUS_PENDING_CRYPTO) {
                throw new BadRequestException(__('The group-provisioning request is not pending cryptographic work.'));
            }
            $groupUser = $this->groupsUsersTable()->find()->where([
                'group_id' => $groupId,
                'user_id' => $userId,
            ])->first();
            if (!($groupUser instanceof GroupsUser)) {
                throw new BadRequestException(__('The Passbolt group membership has not been completed.'));
            }
            $membership->set('status', KeycloakSsoGroupMembership::STATUS_ACTIVE);
            $membership->set('failure_code', null);
            $this->membershipsTable()->saveOrFail($membership);

            return [$userId, $groupId, true];
        });
        if ($completed[2] === true) {
            $this->audit->record('membership_completed', 'client_crypto', $completed[0], $completed[1]);
        }
    }

    /** Require a valid internal UUID before any table lookup. */
    private function assertUuid(string $value): void
    {
        if (!Validation::uuid($value)) {
            throw new BadRequestException(__('The group-provisioning identifier is invalid.'));
        }
    }

    /** @return \Passbolt\KeycloakSso\Model\Table\KeycloakSsoGroupMembershipsTable */
    private function membershipsTable(): Table
    {
        return $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoGroupMemberships');
    }

    /** Return the core Passbolt group-membership table. */
    private function groupsUsersTable(): GroupsUsersTable
    {
        /** @var \App\Model\Table\GroupsUsersTable $table */
        $table = $this->fetchTable('GroupsUsers');

        return $table;
    }
}
