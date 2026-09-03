<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Oidc;

use Passbolt\KeycloakSso\Error\Exception\OidcValidationException;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;
use Passbolt\KeycloakSso\Utility\Http\OidcHttpClientInterface;
use SensitiveParameter;

final class AuthorizationCodeExchangeService
{
    /**
     * Construct the code exchange service using trusted discovery metadata.
     */
    public function __construct(
        private readonly OidcConfigurationDto $configuration,
        private readonly OidcDiscoveryService $discovery,
        private readonly OidcHttpClientInterface $httpClient,
    ) {
    }

    /**
     * Redeem a one-time authorization code and return only the ID token.
     */
    public function exchange(
        #[SensitiveParameter]
        string $code,
        #[SensitiveParameter]
        string $pkceVerifier
    ): string {
        if ($code === '' || strlen($code) > 4096 || preg_match('/[\x00-\x1F\x7F]/', $code)) {
            throw new OidcValidationException('invalid_authorization_code');
        }
        $response = $this->httpClient->requestJson('POST', $this->discovery->get()->tokenEndpoint, [
            'grant_type' => 'authorization_code',
            'client_id' => $this->configuration->clientId,
            'client_secret' => $this->configuration->clientSecret,
            'redirect_uri' => $this->configuration->redirectUri,
            'code' => $code,
            'code_verifier' => $pkceVerifier,
        ]);
        $idToken = $response['id_token'] ?? null;
        if (!is_string($idToken) || $idToken === '' || strlen($idToken) > 32_768) {
            throw new OidcValidationException('missing_or_invalid_id_token');
        }

        return $idToken;
    }
}
