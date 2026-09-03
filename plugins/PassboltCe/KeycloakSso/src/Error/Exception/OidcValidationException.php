<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Error\Exception;

use RuntimeException;

final class OidcValidationException extends RuntimeException
{
    /**
     * Construct a non-sensitive validation failure.
     */
    public function __construct(private readonly string $reasonCode)
    {
        parent::__construct('The OIDC response could not be validated.');
    }

    /**
     * Return an internal allowlisted reason identifier.
     */
    public function reasonCode(): string
    {
        return $this->reasonCode;
    }
}
