<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Transaction;

use Cake\I18n\DateTime;
use Cake\ORM\Locator\LocatorAwareTrait;
use Passbolt\KeycloakSso\Error\Exception\OidcTransactionException;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction;

final class ClaimOidcTransactionService
{
    use LocatorAwareTrait;

    public function __construct(private readonly TransactionSecretProtector $protector)
    {
    }

    /**
     * @return array{transaction: \Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction, pkceVerifier: string}
     */
    public function claim(string $state, string $browserBinding, string $configurationHash): array
    {
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
        $pkceVerifier = $this->protector->decrypt(
            (string)$transaction->pkce_verifier_ciphertext,
            $associatedData
        );
        $transaction->status = KeycloakSsoTransaction::STATUS_PROCESSING;

        return ['transaction' => $transaction, 'pkceVerifier' => $pkceVerifier];
    }

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

    public function consumeResult(string $resultToken): void
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
