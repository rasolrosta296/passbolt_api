<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Dto;

final readonly class KeycloakProvisioningGroupDto
{
    /** Construct one validated Keycloak group snapshot. */
    public function __construct(
        public string $id,
        public string $name,
        public string $path,
    ) {
    }

    /** Use the full immutable-identity-associated path as the initial Passbolt display name. */
    public function passboltName(): string
    {
        return ltrim($this->path, '/');
    }
}
