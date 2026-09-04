<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Oidc;

use InvalidArgumentException;
use Passbolt\KeycloakSso\Model\Dto\CreatedOidcTransaction;
use Passbolt\KeycloakSso\Model\Dto\OidcAuthorizationRequest;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;
use Passbolt\KeycloakSso\Service\Transaction\CreateOidcTransactionService;

final class AuthorizationRequestService implements AuthorizationRequestProviderInterface
{
    /**
     * Construct the authorization request service.
     */
    public function __construct(
        private readonly OidcConfigurationDto $configuration,
        private readonly OidcDiscoveryService $discovery,
        private readonly CreateOidcTransactionService $transactions,
    ) {
    }

    /**
     * Create the transaction and its trusted-provider redirect.
     */
    public function create(): OidcAuthorizationRequest
    {
        $discovery = $this->discovery->get();
        $transaction = $this->transactions->create(
            $this->configuration->issuer,
            $this->configuration->clientId,
            $this->configuration->redirectUri,
            $this->configuration->configurationHash(),
            OidcConfigurationDto::TRANSACTION_TTL_SECONDS
        );

        return new OidcAuthorizationRequest(
            self::buildAuthorizationUrl($this->configuration, $discovery->authorizationEndpoint, $transaction),
            $transaction->browserBinding
        );
    }

    /**
     * Build an Authorization Code Flow URL with nonce, state, and PKCE S256.
     */
    public static function buildAuthorizationUrl(
        OidcConfigurationDto $configuration,
        string $authorizationEndpoint,
        CreatedOidcTransaction $transaction,
        array $additionalParameters = []
    ): string {
        $parameters = [
            'response_type' => 'code',
            'response_mode' => 'query',
            'client_id' => $configuration->clientId,
            'redirect_uri' => $configuration->redirectUri,
            'scope' => 'openid email',
            'state' => $transaction->state,
            'nonce' => $transaction->nonce,
            'code_challenge' => $transaction->pkceChallenge,
            'code_challenge_method' => 'S256',
        ];
        foreach ($additionalParameters as $name => $value) {
            if (!is_string($name) || !is_string($value) || array_key_exists($name, $parameters)) {
                throw new InvalidArgumentException('Invalid additional authorization parameter.');
            }
            $parameters[$name] = $value;
        }
        $query = http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);

        return $authorizationEndpoint . '?' . $query;
    }
}
