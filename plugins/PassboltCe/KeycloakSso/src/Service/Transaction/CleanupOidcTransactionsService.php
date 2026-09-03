<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Transaction;

use Cake\I18n\DateTime;
use Cake\ORM\Locator\LocatorAwareTrait;
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

        return ['expired' => $expired, 'results' => $results, 'deleted' => $deleted];
    }
}
