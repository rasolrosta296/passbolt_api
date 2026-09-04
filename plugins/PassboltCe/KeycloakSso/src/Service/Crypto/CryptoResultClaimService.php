<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Crypto;

use Cake\Datasource\ConnectionManager;
use Cake\I18n\DateTime;
use Cake\ORM\Locator\LocatorAwareTrait;
use Passbolt\KeycloakSso\Error\Exception\CryptoSsoException;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoCryptoRequest;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction;
use Passbolt\KeycloakSso\Service\Transaction\CreateOidcTransactionService;
use SensitiveParameter;

final class CryptoResultClaimService
{
    use LocatorAwareTrait;

    /** @return array{transaction: \Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction, request: \Passbolt\KeycloakSso\Model\Entity\KeycloakSsoCryptoRequest} */
    public function claim(#[SensitiveParameter]
    string $resultToken, string $purpose): array
    {
        if (preg_match('/^[A-Za-z0-9_-]{43}$/D', $resultToken) !== 1) {
            throw new CryptoSsoException('release_capability_invalid');
        }
        $transactionPurpose = match ($purpose) {
            KeycloakSsoCryptoRequest::PURPOSE_ENROLLMENT => KeycloakSsoTransaction::PURPOSE_CRYPTO_ENROLLMENT,
            KeycloakSsoCryptoRequest::PURPOSE_RELEASE => KeycloakSsoTransaction::PURPOSE_CRYPTO_RELEASE,
            default => throw new CryptoSsoException('crypto_result_purpose_invalid'),
        };
        $transactions = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoTransactions');
        $requests = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoCryptoRequests');
        $hash = CreateOidcTransactionService::hash($resultToken);
        $now = DateTime::now();
        /** @var \Cake\Database\Connection $connection */
        $connection = ConnectionManager::get('default');

        return $connection->transactional(function () use (
            $transactions,
            $requests,
            $hash,
            $now,
            $purpose,
            $transactionPurpose
        ): array {
            /** @var \Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction|null $transaction */
            $transaction = $transactions->find()->where([
                'result_token_hash' => $hash,
                'purpose' => $transactionPurpose,
                'status' => KeycloakSsoTransaction::STATUS_SUCCEEDED,
                'result_expires >' => $now,
                'crypto_request_id IS NOT' => null,
            ])->first();
            if ($transaction === null) {
                throw new CryptoSsoException('release_capability_invalid');
            }
            $transactionUpdated = $transactions->updateAll([
                'status' => KeycloakSsoTransaction::STATUS_CRYPTO_PROCESSING,
                'result_token_hash' => null,
                'modified' => $now,
            ], [
                'id' => $transaction->id,
                'status' => KeycloakSsoTransaction::STATUS_SUCCEEDED,
                'result_token_hash' => $hash,
            ]);
            $requestUpdated = $requests->updateAll([
                'status' => KeycloakSsoCryptoRequest::STATUS_PROCESSING,
                'modified' => $now,
            ], [
                'id' => $transaction->crypto_request_id,
                'purpose' => $purpose,
                'status' => KeycloakSsoCryptoRequest::STATUS_OIDC_VERIFIED,
                'expires >' => $now,
            ]);
            if ($transactionUpdated !== 1 || $requestUpdated !== 1) {
                throw new CryptoSsoException('release_capability_replayed');
            }
            $transaction->status = KeycloakSsoTransaction::STATUS_CRYPTO_PROCESSING;
            /** @var \Passbolt\KeycloakSso\Model\Entity\KeycloakSsoCryptoRequest $request */
            $request = $requests->get($transaction->crypto_request_id);

            return ['transaction' => $transaction, 'request' => $request];
        });
    }

    /**
     * Atomically mark a claimed result and request as consumed.
     */
    public function consume(string $transactionId, string $requestId): void
    {
        $now = DateTime::now();
        $transactions = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoTransactions');
        $requests = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoCryptoRequests');
        /** @var \Cake\Database\Connection $connection */
        $connection = ConnectionManager::get('default');
        $connection->transactional(function () use ($transactions, $requests, $transactionId, $requestId, $now): void {
            $a = $transactions->updateAll([
                'status' => KeycloakSsoTransaction::STATUS_RESULT_CONSUMED,
                'result_expires' => null,
                'modified' => $now,
            ], ['id' => $transactionId, 'status' => KeycloakSsoTransaction::STATUS_CRYPTO_PROCESSING]);
            $b = $requests->updateAll([
                'status' => KeycloakSsoCryptoRequest::STATUS_CONSUMED,
                'request_ciphertext' => null,
                'modified' => $now,
            ], ['id' => $requestId, 'status' => KeycloakSsoCryptoRequest::STATUS_PROCESSING]);
            if ($a !== 1 || $b !== 1) {
                throw new CryptoSsoException('crypto_result_consumption_failed');
            }
        });
    }

    /**
     * Terminally fail a claimed result and erase request ciphertext.
     */
    public function fail(string $transactionId, string $requestId): void
    {
        $now = DateTime::now();
        $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoTransactions')->updateAll([
            'status' => KeycloakSsoTransaction::STATUS_FAILED,
            'result_token_hash' => null,
            'result_expires' => null,
            'failure_code' => 'crypto_operation_failed',
            'modified' => $now,
        ], ['id' => $transactionId, 'status' => KeycloakSsoTransaction::STATUS_CRYPTO_PROCESSING]);
        $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoCryptoRequests')->updateAll([
            'status' => KeycloakSsoCryptoRequest::STATUS_FAILED,
            'request_ciphertext' => null,
            'modified' => $now,
        ], ['id' => $requestId, 'status' => KeycloakSsoCryptoRequest::STATUS_PROCESSING]);
    }
}
