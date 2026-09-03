<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Identity;

use Cake\I18n\DateTime;
use Cake\ORM\Locator\LocatorAwareTrait;
use Passbolt\KeycloakSso\Error\Exception\IdentityLinkException;
use Passbolt\KeycloakSso\Model\Dto\ValidatedOidcIdentity;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction;
use Passbolt\KeycloakSso\Service\Audit\IdentityLinkAuditService;
use Throwable;

final class PrepareIdentityLinkService
{
    use LocatorAwareTrait;

    /** Construct the validated-identity preparation service. */
    public function __construct(
        private readonly ExistingUserDiscoveryService $users,
        private readonly IdentityLinkPersistenceService $links,
        private readonly IdentityLinkProofProtector $protector,
        private readonly ?IdentityLinkAuditService $audit = null,
    ) {
    }

    /**
     * Bind a freshly validated OIDC identity to its original authenticated-user request.
     */
    public function prepare(KeycloakSsoTransaction $transaction, ValidatedOidcIdentity $identity): void
    {
        if (
            $transaction->purpose !== KeycloakSsoTransaction::PURPOSE_IDENTITY_LINK ||
            !is_string($transaction->requested_user_id)
        ) {
            throw new IdentityLinkException('link_transaction_invalid');
        }

        $audit = $this->audit ?? new IdentityLinkAuditService();
        try {
            $candidate = $this->users->findExactlyOne($identity->email);
            if (!hash_equals($transaction->requested_user_id, $candidate->id)) {
                throw new IdentityLinkException('identity_mismatch');
            }
            $this->links->assertAvailable($candidate->id, $transaction->issuer, $identity->subject);
        } catch (Throwable $exception) {
            if (
                $exception instanceof IdentityLinkException &&
                in_array($exception->reasonCode(), [
                    'identity_already_linked',
                    'provider_identity_collision',
                    'provider_user_collision',
                    'database_identity_collision',
                ], true)
            ) {
                $audit->collision($transaction->requested_user_id);
                $audit->linkFailed($transaction->requested_user_id, 'collision');
            } else {
                $audit->linkFailed($transaction->requested_user_id, 'identity_mismatch');
            }
            throw $exception;
        }

        $ciphertext = $this->protector->protect(
            $transaction,
            $transaction->issuer,
            $identity
        );
        $affected = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoTransactions')->updateAll(
            ['link_identity_ciphertext' => $ciphertext, 'modified' => DateTime::now()],
            ['id' => $transaction->id, 'status' => KeycloakSsoTransaction::STATUS_PROCESSING]
        );
        if ($affected !== 1) {
            $audit->linkFailed($transaction->requested_user_id, 'transaction_invalid');
            throw new IdentityLinkException('link_transaction_invalid');
        }
    }
}
