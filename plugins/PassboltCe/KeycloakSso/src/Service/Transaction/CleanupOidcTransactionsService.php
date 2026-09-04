<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Transaction;

use Cake\I18n\DateTime;
use Cake\ORM\Locator\LocatorAwareTrait;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoCryptoRequest;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction;

final class CleanupOidcTransactionsService
{
    use LocatorAwareTrait;

    public const TERMINAL_RETENTION_SECONDS = 86_400;

    /**
     * Erase expired secret material and remove old terminal transactions.
     *
     * @return array{expired: int, results: int, deleted: int}
     */
    public function run(?DateTime $now = null): array
    {
        $now ??= DateTime::now();
        $table = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoTransactions');
        $expired = $table->updateAll(
            [
                'status' => KeycloakSsoTransaction::STATUS_FAILED,
                'failure_code' => 'transaction_expired',
                'pkce_verifier_ciphertext' => null,
                'result_token_hash' => null,
                'link_identity_ciphertext' => null,
                'modified' => $now,
            ],
            [
                'status IN' => [
                    KeycloakSsoTransaction::STATUS_PENDING,
                    KeycloakSsoTransaction::STATUS_PROCESSING,
                    KeycloakSsoTransaction::STATUS_LINKING,
                    KeycloakSsoTransaction::STATUS_CRYPTO_PROCESSING,
                ],
                'expires <=' => $now,
            ]
        );
        $results = $table->updateAll(
            [
                'status' => KeycloakSsoTransaction::STATUS_RESULT_CONSUMED,
                'result_token_hash' => null,
                'link_identity_ciphertext' => null,
                'modified' => $now,
            ],
            [
                'status' => KeycloakSsoTransaction::STATUS_SUCCEEDED,
                'result_expires <=' => $now,
            ]
        );
        $deleted = $table->deleteAll([
            'status IN' => [
                KeycloakSsoTransaction::STATUS_FAILED,
                KeycloakSsoTransaction::STATUS_RESULT_CONSUMED,
            ],
            'modified <' => $now->subSeconds(self::TERMINAL_RETENTION_SECONDS),
        ]);

        $cryptoRequests = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoCryptoRequests');
        $cryptoRequests->updateAll([
            'status' => KeycloakSsoCryptoRequest::STATUS_FAILED,
            'request_ciphertext' => null,
            'modified' => $now,
        ], [
            'status IN' => [
                KeycloakSsoCryptoRequest::STATUS_PENDING_OIDC,
                KeycloakSsoCryptoRequest::STATUS_OIDC_VERIFIED,
                KeycloakSsoCryptoRequest::STATUS_PROCESSING,
            ],
            'expires <=' => $now,
        ]);
        $deleted += $cryptoRequests->deleteAll([
            'status IN' => [
                KeycloakSsoCryptoRequest::STATUS_FAILED,
                KeycloakSsoCryptoRequest::STATUS_CONSUMED,
            ],
            'modified <' => $now->subSeconds(self::TERMINAL_RETENTION_SECONDS),
        ]);

        return ['expired' => $expired, 'results' => $results, 'deleted' => $deleted];
    }
}
