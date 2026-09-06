<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Dto;

use SensitiveParameter;

final readonly class OidcConfigurationDto
{
    public const TRANSACTION_TTL_SECONDS = 300;
    public const RESULT_TTL_SECONDS = 60;
    public const IDENTITY_LINK_RESULT_TTL_SECONDS = 300;
    public const CRYPTO_RESULT_TTL_SECONDS = 300;
    public const MAX_ID_TOKEN_AGE_SECONDS = 300;
    public const CLOCK_SKEW_SECONDS = 60;
    public const HTTP_TIMEOUT_SECONDS = 5;
    public const MAX_HTTP_RESPONSE_BYTES = 1_048_576;
    public const ALLOWED_ID_TOKEN_ALGORITHMS = ['RS256'];

    /**
     * Construct validated OIDC configuration.
     */
    public function __construct(
        public string $issuer,
        public string $clientId,
        #[SensitiveParameter]
        public string $clientSecret,
        public string $redirectUri,
        #[SensitiveParameter]
        public string $transactionEncryptionKey,
    ) {
    }

    /**
     * Return the issuer-derived discovery URL.
     */
    public function discoveryUrl(): string
    {
        return $this->issuer . '/.well-known/openid-configuration';
    }

    /**
     * Bind transactions to the complete security-relevant configuration.
     */
    public function configurationHash(): string
    {
        return hash_hmac(
            'sha256',
            implode("\0", [$this->issuer, $this->clientId, $this->redirectUri, $this->clientSecret]),
            $this->transactionEncryptionKey
        );
    }
}
