<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Dto;

final readonly class OidcConfigurationDto
{
    public const TRANSACTION_TTL_SECONDS = 300;
    public const RESULT_TTL_SECONDS = 60;
    public const MAX_ID_TOKEN_AGE_SECONDS = 300;
    public const CLOCK_SKEW_SECONDS = 60;
    public const HTTP_TIMEOUT_SECONDS = 5;
    public const MAX_HTTP_RESPONSE_BYTES = 1_048_576;
    public const ALLOWED_ID_TOKEN_ALGORITHMS = ['RS256'];

    public function __construct(
        public string $issuer,
        public string $clientId,
        public string $clientSecret,
        public string $redirectUri,
        public string $transactionEncryptionKey,
    ) {
    }

    public function discoveryUrl(): string
    {
        return $this->issuer . '/.well-known/openid-configuration';
    }

    public function configurationHash(): string
    {
        return hash('sha256', implode("\0", [$this->issuer, $this->clientId, $this->redirectUri]));
    }
}
