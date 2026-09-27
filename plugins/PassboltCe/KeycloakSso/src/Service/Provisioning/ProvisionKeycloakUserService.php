<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Provisioning;

use App\Model\Entity\Role;
use App\Model\Entity\User;
use App\Utility\UserAccessControl;
use App\Utility\UuidFactory;
use Cake\Datasource\ConnectionManager;
use Cake\I18n\DateTime;
use Cake\ORM\Locator\LocatorAwareTrait;
use Cake\ORM\Table;
use Passbolt\KeycloakSso\Error\Exception\OidcNetworkException;
use Passbolt\KeycloakSso\Error\Exception\ProvisioningException;
use Passbolt\KeycloakSso\Model\Dto\KeycloakAdminEventDto;
use Passbolt\KeycloakSso\Model\Dto\KeycloakProvisioningUserDto;
use Passbolt\KeycloakSso\Model\Dto\ProvisioningConfigurationDto;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoProvisioningEvent;
use Passbolt\KeycloakSso\Service\Audit\ProvisioningAuditService;
use Throwable;

final class ProvisionKeycloakUserService
{
    use LocatorAwareTrait;

    public const OUTCOME_PROVISIONED = 'provisioned';
    public const OUTCOME_WOULD_PROVISION = 'would_provision';
    public const OUTCOME_SKIPPED = 'skipped';
    public const OUTCOME_COLLISION = 'collision';
    public const OUTCOME_DUPLICATE = 'duplicate';
    public const OUTCOME_IN_PROGRESS = 'in_progress';
    public const OUTCOME_FAILED = 'failed';

    /** Construct the single-event provisioning service. */
    public function __construct(
        private readonly ProvisioningConfigurationDto $configuration,
        private readonly KeycloakProvisioningApiService $api,
        private readonly ProvisioningAuditService $audit,
    ) {
    }

    /** Process one idempotent Keycloak administrator event. */
    public function process(KeycloakAdminEventDto $event, bool $dryRun = false): string
    {
        if ($dryRun) {
            return $this->dryRun($event);
        }

        $claim = $this->claim($event);
        if ($claim !== null) {
            return $claim;
        }

        try {
            $user = $this->api->user($event->subject);
            $eligibility = $this->eligibilityFailure($user);
            if ($eligibility !== null) {
                $this->finish($event, KeycloakSsoProvisioningEvent::STATUS_SKIPPED, $eligibility);
                $this->audit->record('skipped', $this->auditCategory($eligibility));

                return self::OUTCOME_SKIPPED;
            }
            $actor = $this->activeAdminActor();
            $normalizedEmail = mb_strtolower($user->email, 'UTF-8');
            $collision = $this->collision($event->subject, $normalizedEmail);
            if ($collision !== null) {
                if ($collision === 'subject_already_provisioned') {
                    $this->finish($event, KeycloakSsoProvisioningEvent::STATUS_SKIPPED, $collision);
                    $this->audit->record('skipped');

                    return self::OUTCOME_DUPLICATE;
                }
                $this->finish($event, KeycloakSsoProvisioningEvent::STATUS_COLLISION, $collision);
                $this->audit->record('collision', $this->auditCategory($collision));

                return self::OUTCOME_COLLISION;
            }

            $created = $this->persist($event, $user, $actor, $normalizedEmail);
            $this->audit->record('provisioned', 'none', $created->id);

            return self::OUTCOME_PROVISIONED;
        } catch (Throwable $exception) {
            if ($exception instanceof ProvisioningException && $exception->getMessage() === 'concurrent_collision') {
                $this->finish(
                    $event,
                    KeycloakSsoProvisioningEvent::STATUS_COLLISION,
                    'concurrent_collision'
                );
                $this->audit->record('collision', 'identity_collision');

                return self::OUTCOME_COLLISION;
            }
            $failure = match (true) {
                $exception instanceof OidcNetworkException => 'keycloak_unavailable',
                $exception instanceof ProvisioningException => $exception->getMessage(),
                default => 'unexpected_failure',
            };
            $code = $this->fixedFailureCode($failure);
            $this->finish($event, KeycloakSsoProvisioningEvent::STATUS_FAILED, $code);
            $this->audit->record('failed', $this->auditCategory($code));

            return self::OUTCOME_FAILED;
        }
    }

    /** Recover claims abandoned by a terminated previous command. */
    public function recoverStaleClaims(?DateTime $now = null): int
    {
        $cutoff = ($now ?? DateTime::now())->subMinutes(10);
        $table = $this->eventsTable();

        return $table->updateAll([
            'status' => KeycloakSsoProvisioningEvent::STATUS_FAILED,
            'failure_code' => 'stale_claim',
            'modified' => DateTime::now(),
        ], [
            'status' => KeycloakSsoProvisioningEvent::STATUS_PROCESSING,
            'modified <' => $cutoff,
        ]);
    }

    /** Evaluate one event without creating checkpoints, users, or invitations. */
    private function dryRun(KeycloakAdminEventDto $event): string
    {
        try {
            $user = $this->api->user($event->subject);
            $eligibility = $this->eligibilityFailure($user);
            if ($eligibility !== null) {
                return self::OUTCOME_SKIPPED;
            }
            $this->activeAdminActor();

            return $this->collision($event->subject, mb_strtolower($user->email, 'UTF-8')) === null
                ? self::OUTCOME_WOULD_PROVISION
                : self::OUTCOME_COLLISION;
        } catch (Throwable) {
            return self::OUTCOME_FAILED;
        }
    }

    /** Return a terminal outcome when the event cannot be claimed, otherwise null. */
    private function claim(KeycloakAdminEventDto $event): ?string
    {
        $table = $this->eventsTable();
        $entity = $table->find()->where([
            'issuer' => $this->configuration->issuer,
            'event_id' => $event->eventId,
        ])->first();
        if ($entity === null) {
            $entity = $table->newEmptyEntity();
            foreach (
                [
                'id' => UuidFactory::uuid(),
                'event_id' => $event->eventId,
                'issuer' => $this->configuration->issuer,
                'subject' => $event->subject,
                'event_time' => $event->eventTime,
                'operation' => $event->operation,
                'status' => KeycloakSsoProvisioningEvent::STATUS_PENDING,
                ] as $field => $value
            ) {
                $entity->set($field, $value);
            }
            try {
                $table->saveOrFail($entity);
            } catch (Throwable) {
                $entity = $table->find()->where([
                    'issuer' => $this->configuration->issuer,
                    'event_id' => $event->eventId,
                ])->first();
                if ($entity === null) {
                    throw new ProvisioningException('event_persistence_failed');
                }
            }
        }
        if (
            !hash_equals((string)$entity->get('subject'), $event->subject) ||
            (int)$entity->get('event_time') !== $event->eventTime ||
            !hash_equals((string)$entity->get('operation'), $event->operation)
        ) {
            throw new ProvisioningException('event_identity_mismatch');
        }

        $status = (string)$entity->get('status');
        if (
            in_array($status, [
            KeycloakSsoProvisioningEvent::STATUS_PROVISIONED,
            KeycloakSsoProvisioningEvent::STATUS_SKIPPED,
            KeycloakSsoProvisioningEvent::STATUS_COLLISION,
            ], true)
        ) {
            return self::OUTCOME_DUPLICATE;
        }
        $claimed = $table->updateAll([
            'status' => KeycloakSsoProvisioningEvent::STATUS_PROCESSING,
            'failure_code' => null,
            'modified' => DateTime::now(),
        ], [
            'id' => $entity->get('id'),
            'status IN' => [
                KeycloakSsoProvisioningEvent::STATUS_PENDING,
                KeycloakSsoProvisioningEvent::STATUS_FAILED,
            ],
        ]);

        return $claimed === 1 ? null : self::OUTCOME_IN_PROGRESS;
    }

    /** Return a fixed reason when the current Keycloak user is not eligible. */
    private function eligibilityFailure(KeycloakProvisioningUserDto $user): ?string
    {
        if (!$user->enabled) {
            return 'user_disabled';
        }
        if (!$user->emailVerified) {
            return 'email_unverified';
        }
        if (
            !$this->validEmail($user->email) || !$this->validName($user->firstName) ||
            !$this->validName($user->lastName)
        ) {
            return 'invalid_profile';
        }

        return null;
    }

    /** Load and validate the Passbolt administrator recorded as inviter. */
    private function activeAdminActor(): User
    {
        /** @var \App\Model\Table\UsersTable $users */
        $users = $this->fetchTable('Users');
        $actor = $users->find()->where(['Users.id' => $this->configuration->actorUserId])->first();
        $adminRoleId = $users->Roles->getIdByName(Role::ADMIN);
        if (
            !($actor instanceof User) || !$actor->isActive() || $actor->isDeleted() ||
            $actor->isDisabled() || !hash_equals($adminRoleId, $actor->role_id)
        ) {
            throw new ProvisioningException('actor_unavailable');
        }

        return $actor;
    }

    /** Detect immutable-subject or case-insensitive username collisions. */
    private function collision(string $subject, string $normalizedEmail): ?string
    {
        $provisioned = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoProvisionedUsers');
        if (
            $provisioned->find()->where([
            'issuer' => $this->configuration->issuer,
            'subject' => $subject,
            ])->count() > 0
        ) {
            return 'subject_already_provisioned';
        }
        /** @var \App\Model\Table\UsersTable $users */
        $users = $this->fetchTable('Users');
        if ($users->find()->where(['LOWER(Users.username)' => $normalizedEmail])->count() > 0) {
            return 'email_collision';
        }

        return null;
    }

    /** Atomically create the invitation and immutable provisioning provenance. */
    private function persist(
        KeycloakAdminEventDto $event,
        KeycloakProvisioningUserDto $keycloakUser,
        User $actor,
        string $normalizedEmail
    ): User {
        /** @var \Cake\Database\Connection $connection */
        $connection = ConnectionManager::get('default');

        return $connection->transactional(function () use (
            $event,
            $keycloakUser,
            $actor,
            $normalizedEmail
        ): User {
            $eventEntity = $this->eventsTable()->find()->where([
                'issuer' => $this->configuration->issuer,
                'event_id' => $event->eventId,
                'status' => KeycloakSsoProvisioningEvent::STATUS_PROCESSING,
            ])->epilog('FOR UPDATE')->first();
            if ($eventEntity === null) {
                throw new ProvisioningException('event_claim_lost');
            }
            $actorLocked = $this->fetchTable('Users')->find()->where(['id' => $actor->id])
                ->epilog('FOR UPDATE')->first();
            if (
                !($actorLocked instanceof User) || !$actorLocked->isActive() || $actorLocked->isDeleted() ||
                $actorLocked->isDisabled() || !hash_equals($actor->role_id, $actorLocked->role_id)
            ) {
                throw new ProvisioningException('actor_unavailable');
            }
            if ($this->collision($event->subject, $normalizedEmail) !== null) {
                throw new ProvisioningException('concurrent_collision');
            }

            /** @var \App\Model\Table\UsersTable $users */
            $users = $this->fetchTable('Users');
            $created = $users->register([
                'username' => $normalizedEmail,
                'profile' => [
                    'first_name' => $keycloakUser->firstName,
                    'last_name' => $keycloakUser->lastName,
                ],
            ], new UserAccessControl(Role::ADMIN, $actor->id));

            $provenance = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoProvisionedUsers')->newEmptyEntity();
            foreach (
                [
                'id' => UuidFactory::uuid(),
                'user_id' => $created->id,
                'issuer' => $this->configuration->issuer,
                'subject' => $event->subject,
                'email_at_provisioning' => $normalizedEmail,
                'source_event_id' => $event->eventId,
                ] as $field => $value
            ) {
                $provenance->set($field, $value);
            }
            $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoProvisionedUsers')->saveOrFail($provenance);
            $eventEntity->set('status', KeycloakSsoProvisioningEvent::STATUS_PROVISIONED);
            $eventEntity->set('user_id', $created->id);
            $eventEntity->set('failure_code', null);
            $this->eventsTable()->saveOrFail($eventEntity);

            return $created;
        });
    }

    /** Finish a claimed event without changing any authentication state. */
    private function finish(KeycloakAdminEventDto $event, string $status, string $failureCode): void
    {
        $this->eventsTable()->updateAll([
            'status' => $status,
            'failure_code' => $this->fixedFailureCode($failureCode),
            'modified' => DateTime::now(),
        ], [
            'issuer' => $this->configuration->issuer,
            'event_id' => $event->eventId,
            'status' => KeycloakSsoProvisioningEvent::STATUS_PROCESSING,
        ]);
    }

    /** Reduce internal failures to an allowlisted persistence value. */
    private function fixedFailureCode(string $code): string
    {
        $allowed = [
            'user_disabled', 'email_unverified', 'invalid_profile', 'subject_already_provisioned',
            'email_collision', 'actor_unavailable', 'event_claim_lost', 'event_identity_mismatch',
            'event_persistence_failed', 'concurrent_collision', 'keycloak_unavailable',
            'persistence_failed', 'stale_claim', 'unexpected_failure',
        ];

        return in_array($code, $allowed, true) ? $code : 'unexpected_failure';
    }

    /** Map a fixed internal failure to a data-minimized audit category. */
    private function auditCategory(string $code): string
    {
        return match ($code) {
            'user_disabled' => 'disabled',
            'email_unverified' => 'unverified_email',
            'invalid_profile' => 'invalid_profile',
            'email_collision' => 'existing_user',
            'subject_already_provisioned', 'concurrent_collision' => 'identity_collision',
            'actor_unavailable' => 'actor_unavailable',
            'keycloak_unavailable' => 'keycloak_unavailable',
            'persistence_failed', 'event_persistence_failed' => 'persistence',
            default => 'unexpected',
        };
    }

    /** Validate the bounded email before passing it to core registration. */
    private function validEmail(string $email): bool
    {
        return $email !== '' && strlen($email) <= 255 && trim($email) === $email &&
            filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }

    /** Validate one required, bounded profile name. */
    private function validName(string $name): bool
    {
        return $name !== '' && mb_strlen($name, 'UTF-8') <= 255 && trim($name) === $name &&
            mb_check_encoding($name, 'UTF-8') && preg_match('/[\x00-\x1F\x7F]/', $name) !== 1;
    }

    /** @return \Passbolt\KeycloakSso\Model\Table\KeycloakSsoProvisioningEventsTable */
    private function eventsTable(): Table
    {
        return $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoProvisioningEvents');
    }
}
