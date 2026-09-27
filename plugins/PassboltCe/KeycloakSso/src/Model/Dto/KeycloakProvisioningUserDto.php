<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Dto;

final readonly class KeycloakProvisioningUserDto
{
    /** Construct a strictly typed current Keycloak user snapshot. */
    public function __construct(
        public string $subject,
        public string $email,
        public bool $emailVerified,
        public bool $enabled,
        public string $firstName,
        public string $lastName,
    ) {
    }
}
