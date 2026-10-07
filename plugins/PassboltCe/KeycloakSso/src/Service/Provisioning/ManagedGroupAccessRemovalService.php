<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Provisioning;

use App\Model\Entity\GroupsUser;
use App\Model\Entity\Role;
use App\Model\Entity\Secret;
use App\Service\GroupsUsers\GroupsUsersDeleteService;
use App\Service\Resources\ResourcesExpireResourcesServiceInterface;
use App\Utility\UserAccessControl;
use Cake\I18n\DateTime;
use Cake\ORM\Locator\LocatorAwareTrait;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoGroupMembership;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoProvisionedGroup;

final class ManagedGroupAccessRemovalService
{
    use LocatorAwareTrait;

    /** Construct removal with Passbolt's configured resource-expiry policy. */
    public function __construct(
        private readonly ResourcesExpireResourcesServiceInterface $resourcesExpiry,
    ) {
    }

    /** Remove every plugin-managed membership for one user, idempotently. */
    public function removeAll(string $issuer, string $userId, string $actorUserId): int
    {
        $memberships = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoGroupMemberships')->find()
            ->where([
                'KeycloakSsoGroupMemberships.user_id' => $userId,
            ])
            ->contain(['ProvisionedGroups'])
            ->orderByAsc('KeycloakSsoGroupMemberships.id')
            ->all();
        $removed = 0;
        foreach ($memberships as $membership) {
            $mapping = $membership->get('provisioned_group');
            if (
                !($mapping instanceof KeycloakSsoProvisionedGroup) ||
                !hash_equals($issuer, (string)$mapping->get('issuer'))
            ) {
                continue;
            }
            $groupUser = $this->fetchTable('GroupsUsers')->find()->where([
                'group_id' => $mapping->get('group_id'),
                'user_id' => $userId,
            ])->first();
            if (
                !($groupUser instanceof GroupsUser) &&
                $membership->get('status') === KeycloakSsoGroupMembership::STATUS_REVOKED
            ) {
                continue;
            }
            $this->fetchTable('GroupsUsers')->getConnection()->transactional(function () use (
                $groupUser,
                $actorUserId,
                $membership
            ): void {
                if ($groupUser instanceof GroupsUser) {
                    $changes = (new GroupsUsersDeleteService())->delete(
                        new UserAccessControl(Role::ADMIN, $actorUserId),
                        (string)$groupUser->get('id')
                    );
                    $this->resourcesExpiry->expireResourcesForSecrets(
                        $changes->getDeletedEntities(Secret::class)
                    );
                }
                $membership->set('status', KeycloakSsoGroupMembership::STATUS_REVOKED);
                $membership->set('failure_code', null);
                $membership->set('revoked', DateTime::now());
                $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoGroupMemberships')->saveOrFail($membership);
            });
            $removed++;
        }

        return $removed;
    }
}
