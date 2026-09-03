<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Identity;

use Cake\Datasource\ConnectionManager;
use Cake\I18n\DateTime;
use Cake\ORM\Locator\LocatorAwareTrait;
use Passbolt\KeycloakSso\Error\Exception\IdentityLinkException;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoIdentity;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction;
use Passbolt\KeycloakSso\Service\Audit\IdentityLinkAuditService;
use Passbolt\KeycloakSso\Service\Transaction\CreateOidcTransactionService;
use SensitiveParameter;
use Throwable;

final class ConfirmIdentityLinkService
{
    use LocatorAwareTrait;

    /** Construct the atomic identity confirmation service. */
    public function __construct(
        private readonly string $expectedIssuer,
        private readonly string $configurationHash,
        private readonly ExistingUserDiscoveryService $users,
        private readonly IdentityLinkPersistenceService $links,
        private readonly IdentityLinkProofProtector $protector,
        private readonly IdentityLinkAuditService $audit,
    ) {
    }

    /**
     * Atomically consume the fresh proof and persist exactly one immutable mapping.
     */
    public function confirm(
        #[SensitiveParameter]
        string $resultToken,
        string $userId
    ): KeycloakSsoIdentity {
        $table = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoTransactions');
        $now = DateTime::now();
        $resultHash = CreateOidcTransactionService::hash($resultToken);
        /** @var \Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction|null $candidateTransaction */
        $candidateTransaction = $table->find()->where([
            'result_token_hash' => $resultHash,
            'purpose' => KeycloakSsoTransaction::PURPOSE_IDENTITY_LINK,
            'requested_user_id' => $userId,
        ])->first();
        if ($candidateTransaction === null) {
            $this->audit->linkFailed($userId, 'transaction_invalid');
            throw new IdentityLinkException('link_result_invalid');
        }
        $affected = $table->updateAll(
            [
                'status' => KeycloakSsoTransaction::STATUS_LINKING,
                'result_token_hash' => null,
                'modified' => $now,
            ],
            [
                'id' => $candidateTransaction->id,
                'result_token_hash' => $resultHash,
                'status' => KeycloakSsoTransaction::STATUS_SUCCEEDED,
                'purpose' => KeycloakSsoTransaction::PURPOSE_IDENTITY_LINK,
                'requested_user_id' => $userId,
                'result_expires >' => $now,
                'link_identity_ciphertext IS NOT' => null,
            ]
        );
        if ($affected !== 1) {
            $this->audit->linkFailed($userId, 'transaction_invalid');
            throw new IdentityLinkException('link_result_invalid');
        }

        /** @var \Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction $transaction */
        $transaction = $table->get($candidateTransaction->id);

        try {
            if (
                !hash_equals($this->expectedIssuer, $transaction->issuer) ||
                !hash_equals($this->configurationHash, $transaction->configuration_hash)
            ) {
                throw new IdentityLinkException('link_configuration_changed');
            }
            $identity = $this->protector->reveal($transaction, (string)$transaction->link_identity_ciphertext);
            if (!hash_equals($this->expectedIssuer, $identity->issuer)) {
                throw new IdentityLinkException('link_issuer_changed');
            }
            $candidate = $this->users->findExactlyOne($identity->email);
            if (!hash_equals($userId, $candidate->id)) {
                throw new IdentityLinkException('identity_mismatch');
            }

            /** @var \Cake\Database\Connection $connection */
            $connection = ConnectionManager::get('default');
            $linked = $connection->transactional(function () use ($table, $transaction, $identity, $userId) {
                $saved = $this->links->create($userId, $identity);
                $updated = $table->updateAll(
                    [
                        'status' => KeycloakSsoTransaction::STATUS_RESULT_CONSUMED,
                        'link_identity_ciphertext' => null,
                        'result_expires' => null,
                        'modified' => DateTime::now(),
                    ],
                    ['id' => $transaction->id, 'status' => KeycloakSsoTransaction::STATUS_LINKING]
                );
                if ($updated !== 1) {
                    throw new IdentityLinkException('link_transaction_invalid');
                }

                return $saved;
            });
            $this->audit->linkSucceeded($userId);

            return $linked;
        } catch (Throwable $exception) {
            $table->updateAll(
                [
                    'status' => KeycloakSsoTransaction::STATUS_FAILED,
                    'link_identity_ciphertext' => null,
                    'result_expires' => null,
                    'failure_code' => $exception instanceof IdentityLinkException
                        ? $exception->reasonCode()
                        : 'identity_link_failed',
                    'modified' => DateTime::now(),
                ],
                ['id' => $transaction->id, 'status' => KeycloakSsoTransaction::STATUS_LINKING]
            );
            if (
                $exception instanceof IdentityLinkException &&
                in_array($exception->reasonCode(), [
                    'identity_already_linked',
                    'provider_identity_collision',
                    'provider_user_collision',
                    'database_identity_collision',
                ], true)
            ) {
                $this->audit->collision($userId);
                $this->audit->linkFailed($userId, 'collision');
            } else {
                $this->audit->linkFailed($userId, $this->failureCategory($exception));
            }
            throw $exception;
        }
    }

    /** Reduce internal failures to an audit-safe category. */
    private function failureCategory(Throwable $exception): string
    {
        if (!($exception instanceof IdentityLinkException)) {
            return 'unexpected_failure';
        }

        return match ($exception->reasonCode()) {
            'identity_mismatch' => 'identity_mismatch',
            'identity_persistence_failed' => 'persistence_failure',
            default => 'transaction_invalid',
        };
    }
}
