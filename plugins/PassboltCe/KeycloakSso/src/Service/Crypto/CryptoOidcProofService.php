<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Crypto;

use Cake\I18n\DateTime;
use Cake\ORM\Locator\LocatorAwareTrait;
use Passbolt\KeycloakSso\Configuration\CryptoConfigurationService;
use Passbolt\KeycloakSso\Error\Exception\OidcValidationException;
use Passbolt\KeycloakSso\Model\Dto\CryptoConfigurationDto;
use Passbolt\KeycloakSso\Model\Dto\ValidatedOidcIdentity;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoCryptoRequest;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction;

final class CryptoOidcProofService
{
    use LocatorAwareTrait;

    /**
     * Construct the fresh OIDC proof verifier.
     */
    public function __construct(private ?CryptoConfigurationDto $configuration = null)
    {
    }

    /**
     * Validate and atomically attach a fresh OIDC proof to its crypto request.
     */
    public function verify(KeycloakSsoTransaction $transaction, ValidatedOidcIdentity $oidcIdentity): void
    {
        $this->configuration ??= (new CryptoConfigurationService())->load();
        if ($transaction->crypto_request_id === null || $transaction->requested_user_id === null) {
            throw new OidcValidationException('crypto_request_missing');
        }
        $requestTable = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoCryptoRequests');
        /** @var \Passbolt\KeycloakSso\Model\Entity\KeycloakSsoCryptoRequest|null $request */
        $request = $requestTable->find()->where([
            'id' => $transaction->crypto_request_id,
            'user_id' => $transaction->requested_user_id,
            'status' => KeycloakSsoCryptoRequest::STATUS_PENDING_OIDC,
            'expires >' => DateTime::now(),
        ])->first();
        if ($request === null) {
            throw new OidcValidationException('crypto_request_invalid');
        }
        $expectedPurpose = $transaction->purpose === KeycloakSsoTransaction::PURPOSE_CRYPTO_ENROLLMENT
            ? KeycloakSsoCryptoRequest::PURPOSE_ENROLLMENT
            : KeycloakSsoCryptoRequest::PURPOSE_RELEASE;
        if (!hash_equals($expectedPurpose, (string)$request->get('purpose'))) {
            throw new OidcValidationException('crypto_request_purpose_mismatch');
        }
        $identity = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoIdentities')->find()->where([
            'id' => $request->identity_id,
            'issuer' => $transaction->issuer,
            'subject' => $oidcIdentity->subject,
            'user_id' => $transaction->requested_user_id,
        ])->first();
        if ($identity === null) {
            throw new OidcValidationException('crypto_identity_mismatch');
        }
        $user = $this->fetchTable('Users')->find('activeNotDeletedNotDisabledContainRole')->where([
            'Users.id' => $transaction->requested_user_id,
        ])->first();
        if ($user === null) {
            throw new OidcValidationException('crypto_user_unavailable');
        }
        $created = $transaction->created->getTimestamp();
        if (
            !is_int($oidcIdentity->authTime) ||
            $oidcIdentity->authTime < $created - 60 ||
            $oidcIdentity->authTime > time() + 60
        ) {
            throw new OidcValidationException('oidc_auth_time_not_fresh');
        }
        if (!is_string($oidcIdentity->acr) || !hash_equals($this->configuration->requiredAcr, $oidcIdentity->acr)) {
            throw new OidcValidationException('oidc_acr_mismatch');
        }
        foreach ($this->configuration->requiredAmrValues as $required) {
            if (!in_array($required, $oidcIdentity->amr, true)) {
                throw new OidcValidationException('oidc_amr_mismatch');
            }
        }
        $affected = $requestTable->updateAll(
            ['status' => KeycloakSsoCryptoRequest::STATUS_OIDC_VERIFIED, 'modified' => DateTime::now()],
            ['id' => $request->id, 'status' => KeycloakSsoCryptoRequest::STATUS_PENDING_OIDC]
        );
        if ($affected !== 1) {
            throw new OidcValidationException('crypto_request_replayed');
        }
    }

    /**
     * Terminally fail any crypto request attached to the transaction.
     */
    public function fail(KeycloakSsoTransaction $transaction): void
    {
        if (!is_string($transaction->crypto_request_id)) {
            return;
        }
        $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoCryptoRequests')->updateAll([
            'status' => KeycloakSsoCryptoRequest::STATUS_FAILED,
            'request_ciphertext' => null,
            'modified' => DateTime::now(),
        ], [
            'id' => $transaction->crypto_request_id,
            'status IN' => [
                KeycloakSsoCryptoRequest::STATUS_PENDING_OIDC,
                KeycloakSsoCryptoRequest::STATUS_OIDC_VERIFIED,
            ],
        ]);
    }
}
