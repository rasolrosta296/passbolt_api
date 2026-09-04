<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Dto;

final readonly class CryptoAuthorizationRequest
{
    /**
     * Construct an authorization response without cryptographic secrets.
     */
    public function __construct(
        public string $url,
        public string $browserBinding,
        public string $requestId,
        public string $enrollmentId,
        public string $identityId,
    ) {
    }
}
