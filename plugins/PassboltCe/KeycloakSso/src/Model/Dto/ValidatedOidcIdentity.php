<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Dto;

final readonly class ValidatedOidcIdentity
{
    /**
     * Construct the minimum validated identity claims.
     */
    public function __construct(
        public string $subject,
        public string $email,
    ) {
    }
}
