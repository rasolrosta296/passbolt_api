<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Error\Exception;

use RuntimeException;

final class IdentityLinkException extends RuntimeException
{
    /**
     * Construct a non-sensitive linking failure.
     */
    public function __construct(private readonly string $reasonCode)
    {
        parent::__construct('The Keycloak identity link operation could not be completed.');
    }

    /**
     * Return an internal allowlisted reason identifier.
     */
    public function reasonCode(): string
    {
        return $this->reasonCode;
    }
}
