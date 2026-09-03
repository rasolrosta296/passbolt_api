<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Identity;

use Passbolt\KeycloakSso\Model\Dto\OidcAuthorizationRequest;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction;
use Passbolt\KeycloakSso\Service\Oidc\AuthorizationRequestService;
use Passbolt\KeycloakSso\Service\Oidc\OidcDiscoveryService;
use Passbolt\KeycloakSso\Service\Transaction\CreateOidcTransactionService;

final class IdentityLinkAuthorizationRequestService
{
    /** Construct a purpose-bound authorization request service. */
    public function __construct(
        private readonly OidcConfigurationDto $configuration,
        private readonly OidcDiscoveryService $discovery,
        private readonly CreateOidcTransactionService $transactions,
    ) {
    }

    /**
     * Create a purpose-bound OIDC transaction for the authenticated Passbolt user.
     */
    public function create(string $userId): OidcAuthorizationRequest
    {
        $discovery = $this->discovery->get();
        $transaction = $this->transactions->create(
            $this->configuration->issuer,
            $this->configuration->clientId,
            $this->configuration->redirectUri,
            $this->configuration->configurationHash(),
            OidcConfigurationDto::TRANSACTION_TTL_SECONDS,
            KeycloakSsoTransaction::PURPOSE_IDENTITY_LINK,
            $userId
        );

        return new OidcAuthorizationRequest(
            AuthorizationRequestService::buildAuthorizationUrl(
                $this->configuration,
                $discovery->authorizationEndpoint,
                $transaction
            ),
            $transaction->browserBinding
        );
    }
}
