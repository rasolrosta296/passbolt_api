<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Recovery;

use Passbolt\KeycloakSso\Model\Dto\AccountRecoveryConfigurationDto;
use Passbolt\KeycloakSso\Model\Dto\OidcAuthorizationRequest;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction;
use Passbolt\KeycloakSso\Service\Oidc\AuthorizationRequestService;
use Passbolt\KeycloakSso\Service\Oidc\OidcDiscoveryService;
use Passbolt\KeycloakSso\Service\Transaction\CreateOidcTransactionService;

final class AccountRecoveryAuthorizationService
{
    /**
     * Construct the fresh, interactive recovery identity-proof service.
     */
    public function __construct(
        private readonly OidcConfigurationDto $oidc,
        private readonly AccountRecoveryConfigurationDto $recovery,
        private readonly OidcDiscoveryService $discovery,
        private readonly CreateOidcTransactionService $transactions,
    ) {
    }

    /**
     * Create a browser-bound recovery authorization request.
     *
     * @throws \JsonException
     */
    public function create(): OidcAuthorizationRequest
    {
        $authorizationEndpoint = $this->discovery->get()->authorizationEndpoint;
        $transaction = $this->transactions->create(
            $this->oidc->issuer,
            $this->oidc->clientId,
            $this->oidc->redirectUri,
            $this->oidc->configurationHash(),
            OidcConfigurationDto::TRANSACTION_TTL_SECONDS,
            KeycloakSsoTransaction::PURPOSE_ACCOUNT_RECOVERY
        );
        $url = AuthorizationRequestService::buildAuthorizationUrl(
            $this->oidc,
            $authorizationEndpoint,
            $transaction,
            [
                'prompt' => 'login',
                'max_age' => '0',
                'claims' => json_encode([
                    'id_token' => [
                        'acr' => ['essential' => true, 'value' => $this->recovery->requiredAcr],
                    ],
                ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
            ]
        );

        return new OidcAuthorizationRequest($url, $transaction->browserBinding);
    }
}
