<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Identity;

use App\Model\Validation\EmailValidationRule;
use JsonException;
use Passbolt\KeycloakSso\Error\Exception\IdentityLinkException;
use Passbolt\KeycloakSso\Model\Dto\PendingIdentityLink;
use Passbolt\KeycloakSso\Model\Dto\ValidatedOidcIdentity;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction;
use Passbolt\KeycloakSso\Service\Transaction\TransactionSecretProtector;
use SensitiveParameter;
use Throwable;

final class IdentityLinkProofProtector
{
    /** Construct authenticated protection for short-lived identity proofs. */
    public function __construct(private readonly TransactionSecretProtector $protector)
    {
    }

    /**
     * Protect validated identity data until explicit confirmation.
     */
    public function protect(
        KeycloakSsoTransaction $transaction,
        string $issuer,
        ValidatedOidcIdentity $identity
    ): string {
        try {
            $payload = json_encode([
                'issuer' => $issuer,
                'subject' => $identity->subject,
                'email' => $identity->email,
            ], JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new IdentityLinkException('identity_protection_failed');
        }

        return $this->protector->encrypt($payload, $this->associatedData($transaction));
    }

    /**
     * Authenticate and decode the exact identity observed in the callback.
     */
    public function reveal(
        KeycloakSsoTransaction $transaction,
        #[SensitiveParameter]
        string $ciphertext
    ): PendingIdentityLink {
        try {
            $plaintext = $this->protector->decrypt($ciphertext, $this->associatedData($transaction));
            $payload = json_decode($plaintext, true, 8, JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            throw new IdentityLinkException('identity_protection_failed');
        }
        if (
            !is_array($payload) || array_keys($payload) !== ['issuer', 'subject', 'email'] ||
            !is_string($payload['issuer']) || !hash_equals($transaction->issuer, $payload['issuer']) ||
            !is_string($payload['subject']) || $payload['subject'] === '' || strlen($payload['subject']) > 255 ||
            preg_match('/[\x00-\x1F\x7F]/', $payload['subject']) ||
            !is_string($payload['email']) || !EmailValidationRule::check($payload['email'], true)
        ) {
            throw new IdentityLinkException('identity_protection_failed');
        }

        return new PendingIdentityLink($payload['issuer'], $payload['subject'], $payload['email']);
    }

    /** Bind ciphertext to exactly one transaction and configuration. */
    private function associatedData(KeycloakSsoTransaction $transaction): string
    {
        return $transaction->id . ':' . $transaction->configuration_hash . ':identity-link';
    }
}
