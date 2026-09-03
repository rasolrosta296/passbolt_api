<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Dto;

final readonly class CreatedOidcTransaction
{
    /**
     * Construct an in-memory transaction containing browser-bound secrets.
     */
    public function __construct(
        public string $id,
        public string $state,
        public string $nonce,
        public string $pkceVerifier,
        public string $pkceChallenge,
        public string $browserBinding,
    ) {
    }
}
