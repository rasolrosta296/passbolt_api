<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Provisioning;

use App\Controller\Users\UsersDeleteController;
use App\Model\Entity\Secret;
use App\Model\Entity\User;
use App\Service\Resources\ResourcesExpireResourcesServiceInterface;
use Cake\Datasource\ConnectionManager;
use Cake\Event\EventDispatcherTrait;
use Cake\I18n\DateTime;
use Cake\ORM\Locator\LocatorAwareTrait;
use Cake\Validation\Validation;
use Passbolt\KeycloakSso\Error\Exception\ProvisioningException;
use Passbolt\KeycloakSso\Model\Dto\DeprovisioningConfigurationDto;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoProvisionedUser;
use Passbolt\KeycloakSso\Service\Audit\DeprovisioningAuditService;

final class ProvisionedUserDeletionService
{
    use EventDispatcherTrait;
    use LocatorAwareTrait;

    public const CONFIRMATION = 'DELETE';

    /** Construct the explicitly approved permanent-deletion service. */
    public function __construct(
        private readonly DeprovisioningConfigurationDto $configuration,
        private readonly KeycloakProvisioningApiService $api,
        private readonly ResourcesExpireResourcesServiceInterface $resourcesExpiry,
        private readonly DeprovisioningAuditService $audit = new DeprovisioningAuditService(),
    ) {
    }

    /**
     * Soft-delete one quarantined account after fresh absence confirmation.
     *
     * Core Passbolt ownership and group-manager rules remain authoritative.
     */
    public function delete(string $userId, string $confirmation, ?DateTime $now = null): void
    {
        if (
            !Validation::uuid($userId) ||
            hash_equals($this->configuration->actorUserId, strtolower($userId)) ||
            !hash_equals(self::CONFIRMATION, $confirmation)
        ) {
            throw new ProvisioningException('deletion_confirmation_invalid');
        }
        $now ??= DateTime::now();
        $provisioned = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoProvisionedUsers')->find()->where([
            'issuer' => $this->configuration->issuer,
            'user_id' => strtolower($userId),
        ])->first();
        if ($provisioned === null) {
            throw new ProvisioningException('keycloak_user_not_absent');
        }
        $this->api->assertUserDirectoryAvailable();
        if ($this->api->userOrNull((string)$provisioned->get('subject')) !== null) {
            throw new ProvisioningException('keycloak_user_not_absent');
        }

        /** @var \Cake\Database\Connection $connection */
        $connection = ConnectionManager::get('default');
        $deleted = $connection->transactional(function () use ($userId, $now): array {
            $table = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoProvisionedUsers');
            $provisioned = $table->find()->where([
                'issuer' => $this->configuration->issuer,
                'user_id' => strtolower($userId),
                'lifecycle_status' => KeycloakSsoProvisionedUser::STATUS_QUARANTINED,
                'deprovision_reason' => KeycloakSsoProvisionedUser::REASON_DELETED,
            ])->epilog('FOR UPDATE')->first();
            if (!($provisioned instanceof KeycloakSsoProvisionedUser)) {
                throw new ProvisioningException('deletion_quarantine_active');
            }
            $eligible = $provisioned->get('deletion_eligible_at');
            if (!($eligible instanceof DateTime) || $eligible->greaterThan($now)) {
                throw new ProvisioningException('deletion_quarantine_active');
            }
            /** @var \App\Model\Table\UsersTable $users */
            $users = $this->fetchTable('Users');
            $user = $users->find()->where(['Users.id' => strtolower($userId)])->epilog('FOR UPDATE')->first();
            if (!($user instanceof User) || $user->isDeleted() || !$user->isDisabled()) {
                throw new ProvisioningException('deletion_user_state_invalid');
            }
            /** @var \App\Model\Table\GroupsUsersTable $groupsUsers */
            $groupsUsers = $this->fetchTable('GroupsUsers');
            $groupIds = $groupsUsers->findGroupsWhereUserNotOnlyMember($user->id)
                ->all()->extract('group_id')->toArray();
            $changes = $users->softDelete($user, ['checkRules' => true]);
            if ($changes === false) {
                throw new ProvisioningException('ownership_transfer_required');
            }
            $this->resourcesExpiry->expireResourcesForSecrets($changes->getDeletedEntities(Secret::class));
            $provisioned->set('lifecycle_status', KeycloakSsoProvisionedUser::STATUS_DELETED);
            $provisioned->set('last_checked', $now);
            $table->saveOrFail($provisioned);

            return ['user' => $user, 'group_ids' => $groupIds];
        });
        $this->audit->record('deleted', 'deleted', strtolower($userId));
        $this->dispatchEvent(UsersDeleteController::DELETE_SUCCESS_EVENT_NAME, [
            'user' => $deleted['user'],
            'groupsIds' => $deleted['group_ids'],
            'deletedBy' => $this->configuration->actorUserId,
        ]);
    }
}
