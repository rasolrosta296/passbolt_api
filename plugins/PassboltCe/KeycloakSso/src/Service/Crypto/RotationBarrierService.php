<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Crypto;

use App\Utility\UuidFactory;
use Cake\Datasource\ConnectionManager;
use Cake\I18n\DateTime;
use Cake\ORM\Locator\LocatorAwareTrait;
use Passbolt\KeycloakSso\Error\Exception\CryptoSsoException;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoRotationBarrier;
use Passbolt\KeycloakSso\Service\Transaction\CreateOidcTransactionService;
use Passbolt\KeycloakSso\Service\Transaction\TransactionSecretProtector;
use SensitiveParameter;
use Throwable;

final class RotationBarrierService
{
    use LocatorAwareTrait;

    public const CAPABILITY_AAD_SUFFIX = ':passphrase-rotation';

    /** Construct the server-authoritative rotation barrier. */
    public function __construct(
        private readonly TransactionSecretProtector $protector,
        private readonly RevokeCryptoEnrollmentsService $revocation,
    ) {
    }

    /**
     * Activate the barrier and irreversibly revoke all prior enrollment state.
     *
     * Repeating begin while a barrier is active returns the same capability so
     * a lost response cannot strand the normally authenticated user.
     *
     * @return array{capability: string, clientEnrollmentUuids: list<string>}
     */
    public function begin(string $userId): array
    {
        /** @var \Cake\Database\Connection $connection */
        $connection = ConnectionManager::get('default');

        return $connection->transactional(function () use ($userId): array {
            $this->lockActiveUser($userId);
            $table = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoRotationBarriers');
            /** @var \Passbolt\KeycloakSso\Model\Entity\KeycloakSsoRotationBarrier|null $barrier */
            $barrier = $table->find()->where(['user_id' => $userId])->epilog('FOR UPDATE')->first();
            if ($barrier !== null && $barrier->status === KeycloakSsoRotationBarrier::STATUS_ACTIVE) {
                $capability = $this->decryptCapability($barrier);
            } else {
                $capability = self::randomCapability();
                if ($barrier === null) {
                    $barrier = $table->newEmptyEntity();
                    $barrier->set('id', UuidFactory::uuid());
                }
                $barrier->set('user_id', $userId);
                $barrier->set('capability_hash', CreateOidcTransactionService::hash($capability));
                $barrier->set('capability_ciphertext', $this->protector->encrypt(
                    $capability,
                    (string)$barrier->get('id') . self::CAPABILITY_AAD_SUFFIX
                ));
                $barrier->set('status', KeycloakSsoRotationBarrier::STATUS_ACTIVE);
                $barrier->set('finished', null);
                if (!$table->save($barrier)) {
                    throw new CryptoSsoException('rotation_barrier_creation_failed');
                }
            }

            return [
                'capability' => $capability,
                'clientEnrollmentUuids' => $this->revocation->revokeAllForUser($userId),
            ];
        });
    }

    /** Complete or fail the active barrier without ever restoring revoked shares. */
    public function finish(#[SensitiveParameter]
    string $capability, string $userId, string $outcome): void
    {
        if (
            preg_match('/^[A-Za-z0-9_-]{43}$/D', $capability) !== 1 ||
            !in_array($outcome, [
                KeycloakSsoRotationBarrier::STATUS_COMPLETED,
                KeycloakSsoRotationBarrier::STATUS_FAILED,
            ], true)
        ) {
            throw new CryptoSsoException('rotation_barrier_capability_invalid');
        }
        /** @var \Cake\Database\Connection $connection */
        $connection = ConnectionManager::get('default');
        $connection->transactional(function () use ($capability, $userId, $outcome): void {
            $this->lockActiveUser($userId);
            $table = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoRotationBarriers');
            /** @var \Passbolt\KeycloakSso\Model\Entity\KeycloakSsoRotationBarrier|null $barrier */
            $barrier = $table->find()->where(['user_id' => $userId])->epilog('FOR UPDATE')->first();
            $hash = CreateOidcTransactionService::hash($capability);
            if ($barrier === null || !hash_equals((string)$barrier->get('capability_hash'), $hash)) {
                throw new CryptoSsoException('rotation_barrier_capability_invalid');
            }
            if (hash_equals($outcome, (string)$barrier->get('status'))) {
                return;
            }
            if ($barrier->get('status') !== KeycloakSsoRotationBarrier::STATUS_ACTIVE) {
                throw new CryptoSsoException('rotation_barrier_outcome_conflict');
            }
            $affected = $table->updateAll([
                'status' => $outcome,
                'capability_ciphertext' => null,
                'finished' => DateTime::now(),
                'modified' => DateTime::now(),
            ], [
                'id' => $barrier->id,
                'status' => KeycloakSsoRotationBarrier::STATUS_ACTIVE,
                'capability_hash' => $hash,
            ]);
            if ($affected !== 1) {
                throw new CryptoSsoException('rotation_barrier_finish_race');
            }
        });
    }

    /** Reject cryptographic enrollment or release while rotation is active. */
    public function assertInactive(string $userId): void
    {
        $active = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoRotationBarriers')->exists([
            'user_id' => $userId,
            'status' => KeycloakSsoRotationBarrier::STATUS_ACTIVE,
        ]);
        if ($active) {
            throw new CryptoSsoException('passphrase_rotation_in_progress');
        }
    }

    /** Lock the shared user serialization row and require a usable account. */
    public function lockActiveUser(string $userId): object
    {
        $user = $this->fetchTable('Users')->find('activeNotDeletedNotDisabledContainRole')
            ->where(['Users.id' => $userId])
            ->epilog('FOR UPDATE')
            ->first();
        if ($user === null) {
            throw new CryptoSsoException('rotation_user_unavailable');
        }

        return $user;
    }

    /** Produce a URL-safe 256-bit capability. */
    private static function randomCapability(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    /** Recover only an active barrier capability for authenticated retry. */
    private function decryptCapability(KeycloakSsoRotationBarrier $barrier): string
    {
        try {
            $ciphertext = $barrier->get('capability_ciphertext');
            if (!is_string($ciphertext) || $ciphertext === '') {
                throw new CryptoSsoException('rotation_barrier_corrupt');
            }
            $capability = $this->protector->decrypt(
                $ciphertext,
                $barrier->id . self::CAPABILITY_AAD_SUFFIX
            );
        } catch (Throwable $exception) {
            if ($exception instanceof CryptoSsoException) {
                throw $exception;
            }
            throw new CryptoSsoException('rotation_barrier_corrupt');
        }
        if (
            preg_match('/^[A-Za-z0-9_-]{43}$/D', $capability) !== 1 ||
            !hash_equals(
                (string)$barrier->get('capability_hash'),
                CreateOidcTransactionService::hash($capability)
            )
        ) {
            throw new CryptoSsoException('rotation_barrier_corrupt');
        }

        return $capability;
    }
}
