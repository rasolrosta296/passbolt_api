<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Oidc;

use Passbolt\KeycloakSso\Error\Exception\OidcValidationException;
use Passbolt\KeycloakSso\Model\Dto\OidcCallbackResult;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction;
use Passbolt\KeycloakSso\Service\Identity\ExistingUserDiscoveryService;
use Passbolt\KeycloakSso\Service\Identity\PrepareIdentityLinkService;
use Passbolt\KeycloakSso\Service\Transaction\ClaimOidcTransactionService;
use SensitiveParameter;
use Throwable;

final class OidcCallbackService implements OidcCallbackProcessorInterface
{
    /**
     * Construct the callback validation pipeline.
     */
    public function __construct(
        private readonly OidcConfigurationDto $configuration,
        private readonly ClaimOidcTransactionService $transactions,
        private readonly AuthorizationCodeExchangeService $codeExchange,
        private readonly IdTokenValidationService $idTokenValidation,
        private readonly ExistingUserDiscoveryService $users,
        private readonly ?PrepareIdentityLinkService $identityLinks = null,
    ) {
    }

    /**
     * Atomically consume and validate a successful OIDC callback.
     */
    public function process(
        #[SensitiveParameter]
        string $state,
        #[SensitiveParameter]
        string $browserBinding,
        #[SensitiveParameter]
        string $code
    ): OidcCallbackResult {
        if (!preg_match('/^[A-Za-z0-9_-]{43}$/', $state)) {
            throw new OidcValidationException('invalid_state');
        }
        if (!preg_match('/^[A-Za-z0-9_-]{43}$/', $browserBinding)) {
            throw new OidcValidationException('invalid_browser_binding');
        }

        $claimed = $this->transactions->claim(
            $state,
            $browserBinding,
            $this->configuration->configurationHash()
        );
        $transaction = $claimed['transaction'];
        try {
            if (
                !hash_equals($this->configuration->issuer, $transaction->issuer) ||
                !hash_equals($this->configuration->clientId, $transaction->client_id) ||
                !hash_equals($this->configuration->redirectUri, $transaction->redirect_uri)
            ) {
                throw new OidcValidationException('transaction_configuration_mismatch');
            }
            $idToken = $this->codeExchange->exchange($code, $claimed['pkceVerifier']);
            $identity = $this->idTokenValidation->validate($idToken, $transaction->nonce_hash);
            if ($transaction->purpose === KeycloakSsoTransaction::PURPOSE_IDENTITY_PROOF) {
                $this->users->findExactlyOne($identity->email);
            } elseif ($transaction->purpose === KeycloakSsoTransaction::PURPOSE_IDENTITY_LINK) {
                if ($this->identityLinks === null) {
                    throw new OidcValidationException('identity_link_unavailable');
                }
                $this->identityLinks->prepare($transaction, $identity);
            } else {
                throw new OidcValidationException('invalid_transaction_purpose');
            }

            return new OidcCallbackResult(
                $this->transactions->succeed($transaction->id, OidcConfigurationDto::RESULT_TTL_SECONDS),
                $transaction->purpose
            );
        } catch (Throwable $exception) {
            $reason = $exception instanceof OidcValidationException
                ? $exception->reasonCode()
                : 'oidc_processing_failed';
            $this->transactions->fail($transaction->id, $reason);
            throw $exception;
        }
    }

    /**
     * Terminally consume a callback transaction rejected by the provider.
     */
    public function failProviderResponse(
        #[SensitiveParameter]
        string $state,
        #[SensitiveParameter]
        string $browserBinding
    ): void {
        if (!preg_match('/^[A-Za-z0-9_-]{43}$/', $state) || !preg_match('/^[A-Za-z0-9_-]{43}$/', $browserBinding)) {
            throw new OidcValidationException('invalid_provider_error_callback');
        }
        $claimed = $this->transactions->claim(
            $state,
            $browserBinding,
            $this->configuration->configurationHash()
        );
        $this->transactions->fail($claimed['transaction']->id, 'provider_returned_error');
    }
}
