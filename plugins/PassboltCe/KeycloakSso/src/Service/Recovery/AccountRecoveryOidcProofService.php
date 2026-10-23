<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Recovery;

use Cake\I18n\DateTime;
use Cake\ORM\Locator\LocatorAwareTrait;
use Passbolt\KeycloakSso\Configuration\AccountRecoveryConfigurationService;
use Passbolt\KeycloakSso\Error\Exception\OidcValidationException;
use Passbolt\KeycloakSso\Model\Dto\AccountRecoveryConfigurationDto;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;
use Passbolt\KeycloakSso\Model\Dto\ValidatedOidcIdentity;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction;

final class AccountRecoveryOidcProofService
{
    use LocatorAwareTrait;

    /** Construct with an optional prevalidated policy for tests. */
    public function __construct(
        private readonly AccountRecoveryIdentityProofProtector $identityProofs,
        private ?AccountRecoveryConfigurationDto $configuration = null,
    ) {
    }

    /**
     * Bind a fresh linked Keycloak identity proof to one active Passbolt user.
     */
    public function verify(KeycloakSsoTransaction $transaction, ValidatedOidcIdentity $oidcIdentity): void
    {
        if ($transaction->purpose !== KeycloakSsoTransaction::PURPOSE_ACCOUNT_RECOVERY) {
            throw new OidcValidationException('account_recovery_purpose_mismatch');
        }
        $this->configuration ??= (new AccountRecoveryConfigurationService())->load();
        $identity = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoIdentities')->find()->where([
            'issuer' => $transaction->issuer,
            'subject' => $oidcIdentity->subject,
        ])->first();
        if ($identity === null) {
            throw new OidcValidationException('account_recovery_identity_not_linked');
        }
        $userId = (string)$identity->get('user_id');
        $user = $this->fetchTable('Users')->find('activeNotDeletedNotDisabledContainRole')->where([
            'Users.id' => $userId,
        ])->first();
        if ($user === null) {
            throw new OidcValidationException('account_recovery_user_unavailable');
        }
        $created = $transaction->created->getTimestamp();
        if (
            !is_int($oidcIdentity->authTime) ||
            $oidcIdentity->authTime < $created - OidcConfigurationDto::CLOCK_SKEW_SECONDS ||
            $oidcIdentity->authTime > time() + OidcConfigurationDto::CLOCK_SKEW_SECONDS
        ) {
            throw new OidcValidationException('oidc_auth_time_not_fresh');
        }
        if (
            !is_string($oidcIdentity->acr) ||
            !hash_equals($this->configuration->requiredAcr, $oidcIdentity->acr)
        ) {
            throw new OidcValidationException('oidc_acr_mismatch');
        }
        foreach ($this->configuration->requiredAmrValues as $required) {
            if (!in_array($required, $oidcIdentity->amr, true)) {
                throw new OidcValidationException('oidc_amr_mismatch');
            }
        }

        $identityCiphertext = $this->identityProofs->protect(
            $transaction,
            (string)$identity->get('id'),
            $userId,
            (string)$transaction->issuer,
            $oidcIdentity->subject
        );

        $affected = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoTransactions')->updateAll(
            [
                'requested_user_id' => $userId,
                'link_identity_ciphertext' => $identityCiphertext,
                'modified' => DateTime::now(),
            ],
            [
                'id' => $transaction->id,
                'purpose' => KeycloakSsoTransaction::PURPOSE_ACCOUNT_RECOVERY,
                'status' => KeycloakSsoTransaction::STATUS_PROCESSING,
                'requested_user_id IS' => null,
            ]
        );
        if ($affected !== 1) {
            throw new OidcValidationException('account_recovery_proof_replayed');
        }
        $transaction->set('requested_user_id', $userId);
        $transaction->set('link_identity_ciphertext', $identityCiphertext);
    }
}
