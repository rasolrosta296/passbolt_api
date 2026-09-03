<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Dto;

final readonly class OidcCallbackResult
{
    /**
     * Return only a one-time handle and its server-controlled transaction purpose.
     */
    public function __construct(
        public string $token,
        public string $purpose,
    ) {
    }
}
