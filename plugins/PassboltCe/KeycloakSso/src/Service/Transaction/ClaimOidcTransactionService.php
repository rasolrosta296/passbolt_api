<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Transaction;

use Cake\I18n\DateTime;
use Cake\ORM\Locator\LocatorAwareTrait;
use Passbolt\KeycloakSso\Error\Exception\OidcTransactionException;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction;
use Passbolt\KeycloakSso\Service\Oidc\OidcResultConsumerInterface;
use SensitiveParameter;

final class ClaimOidcTransactionService implements OidcResultConsumerInterface
{
    use LocatorAwareTrait;

    /**
     * Construct the service with authenticated transaction-secret protection.
     */
    public function __construct(private readonly TransactionSecretProtector $protector)
    {
    }

    /**
     * @return array{transaction: \Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction, pkceVerifier: string}
     */
    public function claim(
        #[SensitiveParameter]
        string $state,
        #[SensitiveParameter]
        string $browserBinding,
        string $configurationHash
    ): array {
        $table = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoTransactions');
        /** @var \Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction|null $transaction */
        $transaction = $table->find()
            ->where(['state_hash' => CreateOidcTransactionService::hash($state)])
            ->first();
        if ($transaction === null) {
            throw new OidcTransactionException('The OIDC transaction is invalid or has already been used.');
        }

        $now = DateTime::now();
        $affected = $table->updateAll(
            ['status' => KeycloakSsoTransaction::STATUS_PROCESSING, 'modified' => $now],
            [
                'id' => $transaction->id,
                'status' => KeycloakSsoTransaction::STATUS_PENDING,
                'expires >' => $now,
            ]
        );
        if ($affected !== 1) {
            if ($transaction->isExpired($now)) {
                $table->updateAll(
                    [
                        'status' => KeycloakSsoTransaction::STATUS_FAILED,
                        'failure_code' => 'transaction_expired',
                        'pkce_verifier_ciphertext' => null,
                        'modified' => $now,
                    ],
                    ['id' => $transaction->id, 'status' => KeycloakSsoTransaction::STATUS_PENDING]
                );
            }
            throw new OidcTransactionException('The OIDC transaction is invalid or has already been used.');
        }

        if (!hash_equals($transaction->browser_binding_hash, CreateOidcTransactionService::hash($browserBinding))) {
            $this->fail($transaction->id, 'browser_binding_mismatch');
            throw new OidcTransactionException('The OIDC transaction browser binding is invalid.');
        }
        if (!hash_equals($transaction->configuration_hash, $configurationHash)) {
            $this->fail($transaction->id, 'configuration_changed');
            throw new OidcTransactionException('The OIDC configuration changed during authentication.');
        }

        $associatedData = $transaction->id . ':' . $transaction->configuration_hash;
        try {
            $pkceVerifier = $this->protector->decrypt(
                (string)$transaction->pkce_verifier_ciphertext,
                $associatedData
            );
        } catch (OidcTransactionException $exception) {
            $this->fail($transaction->id, 'protected_secret_invalid');
            throw $exception;
        }
        $transaction->status = KeycloakSsoTransaction::STATUS_PROCESSING;

        return ['transaction' => $transaction, 'pkceVerifier' => $pkceVerifier];
    }

    /**
     * Terminally fail a claimed transaction and erase its PKCE verifier.
     */
    public function fail(string $id, string $failureCode): void
    {
        $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoTransactions')->updateAll(
            [
                'status' => KeycloakSsoTransaction::STATUS_FAILED,
                'failure_code' => $failureCode,
                'pkce_verifier_ciphertext' => null,
                'modified' => DateTime::now(),
            ],
            ['id' => $id, 'status' => KeycloakSsoTransaction::STATUS_PROCESSING]
        );
    }

    /**
     * Complete a claimed transaction and return a one-time result handle.
     */
    public function succeed(string $id, int $resultTtlSeconds): string
    {
        $resultToken = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $affected = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoTransactions')->updateAll(
            [
                'status' => KeycloakSsoTransaction::STATUS_SUCCEEDED,
                'result_token_hash' => CreateOidcTransactionService::hash($resultToken),
                'result_expires' => DateTime::now()->addSeconds($resultTtlSeconds),
                'pkce_verifier_ciphertext' => null,
                'modified' => DateTime::now(),
            ],
            ['id' => $id, 'status' => KeycloakSsoTransaction::STATUS_PROCESSING]
        );
        if ($affected !== 1) {
            throw new OidcTransactionException('The OIDC transaction could not be completed.');
        }

        return $resultToken;
    }

    /**
     * Atomically consume a one-time result handle.
     */
    public function consumeResult(#[SensitiveParameter]
    string $resultToken): void
    {
        $now = DateTime::now();
        $affected = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoTransactions')->updateAll(
            [
                'status' => KeycloakSsoTransaction::STATUS_RESULT_CONSUMED,
                'result_token_hash' => null,
                'modified' => $now,
            ],
            [
                'result_token_hash' => CreateOidcTransactionService::hash($resultToken),
                'status' => KeycloakSsoTransaction::STATUS_SUCCEEDED,
                'result_expires >' => $now,
            ]
        );
        if ($affected !== 1) {
            throw new OidcTransactionException('The OIDC result is invalid or has already been used.');
        }
    }
}
