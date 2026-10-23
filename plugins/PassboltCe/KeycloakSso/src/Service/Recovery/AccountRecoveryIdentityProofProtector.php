<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Recovery;

use Cake\Validation\Validation;
use JsonException;
use Passbolt\KeycloakSso\Error\Exception\OidcTransactionException;
use Passbolt\KeycloakSso\Model\Dto\AccountRecoveryIdentityBinding;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction;
use Passbolt\KeycloakSso\Service\Transaction\TransactionSecretProtector;
use SensitiveParameter;
use Throwable;

final class AccountRecoveryIdentityProofProtector
{
    /** Construct authenticated protection for a short-lived recovery identity binding. */
    public function __construct(private readonly TransactionSecretProtector $protector)
    {
    }

    /** Protect the exact persistent identity observed during the validated callback. */
    public function protect(
        KeycloakSsoTransaction $transaction,
        string $identityId,
        string $userId,
        string $issuer,
        string $subject
    ): string {
        try {
            $payload = json_encode([
                'identity_id' => $identityId,
                'user_id' => $userId,
                'issuer' => $issuer,
                'subject' => $subject,
            ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        } catch (JsonException) {
            throw new OidcTransactionException('The account recovery identity proof could not be protected.');
        }

        return $this->protector->encrypt($payload, $this->associatedData($transaction));
    }

    /** Authenticate and decode the exact persistent identity observed during the callback. */
    public function reveal(
        KeycloakSsoTransaction $transaction,
        #[SensitiveParameter]
        string $ciphertext
    ): AccountRecoveryIdentityBinding {
        try {
            $plaintext = $this->protector->decrypt($ciphertext, $this->associatedData($transaction));
            $payload = json_decode($plaintext, true, 8, JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            throw new OidcTransactionException('The account recovery identity proof is invalid.');
        }
        if (
            !is_array($payload) ||
            array_keys($payload) !== ['identity_id', 'user_id', 'issuer', 'subject'] ||
            !is_string($payload['identity_id']) || !Validation::uuid($payload['identity_id']) ||
            !is_string($payload['user_id']) || !Validation::uuid($payload['user_id']) ||
            !is_string($payload['issuer']) || !hash_equals($transaction->issuer, $payload['issuer']) ||
            !is_string($payload['subject']) || $payload['subject'] === '' || strlen($payload['subject']) > 255 ||
            preg_match('/[\x00-\x1F\x7F]/', $payload['subject'])
        ) {
            throw new OidcTransactionException('The account recovery identity proof is invalid.');
        }

        return new AccountRecoveryIdentityBinding(
            $payload['identity_id'],
            $payload['user_id'],
            $payload['issuer'],
            $payload['subject']
        );
    }

    /** Bind protected identity material to this transaction, configuration, and purpose. */
    private function associatedData(KeycloakSsoTransaction $transaction): string
    {
        return $transaction->id . ':' . $transaction->configuration_hash . ':account-recovery-identity';
    }
}
