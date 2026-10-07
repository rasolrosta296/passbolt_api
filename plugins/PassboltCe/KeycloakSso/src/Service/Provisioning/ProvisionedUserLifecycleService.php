<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Provisioning;

use App\Model\Entity\Role;
use App\Model\Entity\Secret;
use App\Model\Entity\User;
use App\Service\Resources\ResourcesExpireResourcesServiceInterface;
use Cake\Datasource\ConnectionManager;
use Cake\I18n\DateTime;
use Cake\ORM\Locator\LocatorAwareTrait;
use Passbolt\KeycloakSso\Error\Exception\IdentityLinkException;
use Passbolt\KeycloakSso\Error\Exception\ProvisioningException;
use Passbolt\KeycloakSso\Model\Dto\DeprovisioningConfigurationDto;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoProvisionedUser;
use Passbolt\KeycloakSso\Service\Audit\DeprovisioningAuditService;
use Passbolt\KeycloakSso\Service\Audit\IdentityLinkAuditService;
use Passbolt\KeycloakSso\Service\Crypto\RevokeCryptoEnrollmentsService;
use Passbolt\KeycloakSso\Service\Identity\UnlinkIdentityService;
use Throwable;

final class ProvisionedUserLifecycleService
{
    use LocatorAwareTrait;

    public const OUTCOME_ACTIVE = 'active';
    public const OUTCOME_WOULD_DEPROVISION = 'would_deprovision';
    public const OUTCOME_DEPROVISIONED = 'deprovisioned';
    public const OUTCOME_IN_PROGRESS = 'in_progress';
    public const OUTCOME_REACTIVATION_REQUIRED = 'reactivation_required';
    public const OUTCOME_FAILED = 'failed';

    /** Construct authoritative lifecycle reconciliation. */
    public function __construct(
        private readonly DeprovisioningConfigurationDto $configuration,
        private readonly KeycloakProvisioningApiService $api,
        private readonly ManagedGroupAccessRemovalService $groupRemoval,
        private readonly ResourcesExpireResourcesServiceInterface $resourcesExpiry,
        private readonly DeprovisioningAuditService $audit = new DeprovisioningAuditService(),
        private readonly RevokeCryptoEnrollmentsService $cryptoRevocation = new RevokeCryptoEnrollmentsService(),
    ) {
    }

    /** @return array<string, int> */
    public function run(bool $dryRun = false, ?DateTime $now = null): array
    {
        $counts = array_fill_keys([
            self::OUTCOME_ACTIVE,
            self::OUTCOME_WOULD_DEPROVISION,
            self::OUTCOME_DEPROVISIONED,
            self::OUTCOME_IN_PROGRESS,
            self::OUTCOME_REACTIVATION_REQUIRED,
            self::OUTCOME_FAILED,
        ], 0);
        $now ??= DateTime::now();
        $this->api->assertUserDirectoryAvailable();
        $lastId = null;
        do {
            $query = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoProvisionedUsers')->find()
                ->contain(['Users'])
                ->where([
                    'issuer' => $this->configuration->issuer,
                    'lifecycle_status !=' => KeycloakSsoProvisionedUser::STATUS_DELETED,
                ])
                ->orderByAsc('KeycloakSsoProvisionedUsers.id')
                ->limit($this->configuration->batchSize);
            if ($lastId !== null) {
                $query->where(['KeycloakSsoProvisionedUsers.id >' => $lastId]);
            }
            $rows = $query->all();
            $received = $rows->count();
            foreach ($rows as $provisioned) {
                try {
                    if (!($provisioned instanceof KeycloakSsoProvisionedUser)) {
                        throw new ProvisioningException('provisioned_user_unavailable');
                    }
                    $lastId = (string)$provisioned->get('id');
                    $remote = $this->api->userOrNull((string)$provisioned->get('subject'));
                    if ($remote !== null && $remote->enabled) {
                        $status = (string)$provisioned->get('lifecycle_status');
                        $user = $provisioned->get('user');
                        if (
                            $status !== KeycloakSsoProvisionedUser::STATUS_ACTIVE ||
                            !($user instanceof User) || $user->isDisabled() || $user->isDeleted()
                        ) {
                            if (!$dryRun) {
                                $this->markReactivationRequired((string)$provisioned->get('id'), $now);
                            }
                            $counts[self::OUTCOME_REACTIVATION_REQUIRED]++;
                        } else {
                            if (!$dryRun) {
                                $this->markActive((string)$provisioned->get('id'), $now);
                            }
                            $counts[self::OUTCOME_ACTIVE]++;
                        }
                        continue;
                    }
                    if ($dryRun) {
                        $counts[self::OUTCOME_WOULD_DEPROVISION]++;
                        continue;
                    }
                    $reason = $remote === null
                        ? KeycloakSsoProvisionedUser::REASON_DELETED
                        : KeycloakSsoProvisionedUser::REASON_DISABLED;
                    if ($this->deprovision((string)$provisioned->get('id'), $reason, $now)) {
                        $counts[self::OUTCOME_DEPROVISIONED]++;
                    } else {
                        $counts[self::OUTCOME_IN_PROGRESS]++;
                    }
                } catch (Throwable) {
                    $this->audit->record('failed', 'unexpected', (string)$provisioned->get('user_id'));
                    $counts[self::OUTCOME_FAILED]++;
                }
            }
        } while ($received === $this->configuration->batchSize);

        return $counts;
    }

    /** Immediately disable access, revoke SSO, unlink identity, and remove managed groups. */
    private function deprovision(string $provisionedId, string $reason, DateTime $now): bool
    {
        /** @var \Cake\Database\Connection $connection */
        $connection = ConnectionManager::get('default');
        $claim = $connection->transactional(
            fn (): ?array => $this->claimDeprovisioning($provisionedId, $reason, $now)
        );
        if ($claim === null) {
            return false;
        }
        $userId = $claim['user_id'];
        $actor = $this->activeAdminActor();
        $this->cryptoRevocation->revokeAllForUser($userId);
        $this->resourcesExpiry->expireResourcesForSecrets($claim['secrets']);
        try {
            (new UnlinkIdentityService(
                $this->configuration->issuer,
                new IdentityLinkAuditService()
            ))->unlink($userId);
        } catch (IdentityLinkException $exception) {
            if ($exception->reasonCode() !== 'identity_not_linked') {
                throw $exception;
            }
        }
        $this->groupRemoval->removeAll($this->configuration->issuer, $userId, $actor->id);

        $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoProvisionedUsers')->updateAll([
            'lifecycle_status' => $reason === KeycloakSsoProvisionedUser::REASON_DELETED
                ? KeycloakSsoProvisionedUser::STATUS_QUARANTINED
                : KeycloakSsoProvisionedUser::STATUS_DEPROVISIONED,
            'last_checked' => $now,
            'modified' => $now,
        ], [
            'id' => $provisionedId,
            'lifecycle_status' => KeycloakSsoProvisionedUser::STATUS_DEPROVISIONING,
            'deprovision_reason' => $reason,
        ]);
        $this->audit->record(
            'deprovisioned',
            $reason === KeycloakSsoProvisionedUser::REASON_DELETED ? 'deleted' : 'disabled',
            $userId
        );

        return true;
    }

    /**
     * Lock the shared user row, disable it, and persist a recoverable cleanup claim.
     *
     * @return array{user_id: string, secrets: list<\App\Model\Entity\Secret>}|null
     */
    private function claimDeprovisioning(string $provisionedId, string $reason, DateTime $now): ?array
    {
        $table = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoProvisionedUsers');
        $row = $table->find()->where(['id' => $provisionedId])->epilog('FOR UPDATE')->firstOrFail();
        $modified = $row->get('modified');
        if (
            $row->get('lifecycle_status') === KeycloakSsoProvisionedUser::STATUS_DEPROVISIONING &&
            $modified instanceof DateTime && $modified->greaterThan($now->subMinutes(10))
        ) {
            return null;
        }
        /** @var \App\Model\Table\UsersTable $users */
        $users = $this->fetchTable('Users');
        $user = $users->find()->where(['Users.id' => $row->get('user_id')])->epilog('FOR UPDATE')->first();
        if (!($user instanceof User) || $user->isDeleted()) {
            $row->set('lifecycle_status', KeycloakSsoProvisionedUser::STATUS_DELETED);
            $row->set('last_checked', $now);
            $table->saveOrFail($row);

            return ['user_id' => (string)$row->get('user_id'), 'secrets' => []];
        }
        $secrets = [];
        if (!$user->isDisabled()) {
            $changes = $users->disableUser($user);
            /** @var list<\App\Model\Entity\Secret> $secrets */
            $secrets = $changes->getDeletedEntities(Secret::class);
        } else {
            /** @var list<\App\Model\Entity\Secret> $secrets */
            $secrets = $this->fetchTable('Secrets')->find()
                ->select(['id', 'user_id', 'resource_id'])
                ->where(['user_id' => $user->id])
                ->all()
                ->toList();
        }
        $previousReason = (string)$row->get('deprovision_reason');
        $row->set('lifecycle_status', KeycloakSsoProvisionedUser::STATUS_DEPROVISIONING);
        $row->set('deprovision_reason', $reason);
        $row->set('last_checked', $now);
        $row->set('deprovisioned_at', $row->get('deprovisioned_at') ?? $now);
        if ($reason === KeycloakSsoProvisionedUser::REASON_DELETED) {
            $newAbsence = $previousReason !== KeycloakSsoProvisionedUser::REASON_DELETED;
            $row->set('absent_since', $newAbsence ? $now : ($row->get('absent_since') ?? $now));
            $row->set(
                'deletion_eligible_at',
                $newAbsence
                    ? $now->addSeconds($this->configuration->graceSeconds)
                    : ($row->get('deletion_eligible_at') ?? $now->addSeconds($this->configuration->graceSeconds))
            );
        } else {
            $row->set('absent_since', null);
            $row->set('deletion_eligible_at', null);
        }
        $table->saveOrFail($row);

        return ['user_id' => $user->id, 'secrets' => $secrets];
    }

    /** Record a healthy remote observation without changing Passbolt activation state. */
    private function markActive(string $id, DateTime $now): void
    {
        $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoProvisionedUsers')->updateAll([
            'lifecycle_status' => KeycloakSsoProvisionedUser::STATUS_ACTIVE,
            'last_seen' => $now,
            'last_checked' => $now,
            'absent_since' => null,
            'deprovision_reason' => null,
            'deletion_eligible_at' => null,
            'modified' => $now,
        ], ['id' => $id, 'lifecycle_status' => KeycloakSsoProvisionedUser::STATUS_ACTIVE]);
    }

    /** Require explicit Passbolt-side review before restoring a deprovisioned account. */
    private function markReactivationRequired(string $id, DateTime $now): void
    {
        $table = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoProvisionedUsers');
        $row = $table->get($id);
        $row->set('lifecycle_status', KeycloakSsoProvisionedUser::STATUS_REACTIVATION_REQUIRED);
        $row->set('last_seen', $now);
        $row->set('last_checked', $now);
        $row->set('absent_since', null);
        $row->set('deletion_eligible_at', null);
        $table->saveOrFail($row);
        $this->audit->record('reactivation_required', 'none', (string)$row->get('user_id'));
    }

    /** Load the configured active administrator used by normal group operations. */
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
}
