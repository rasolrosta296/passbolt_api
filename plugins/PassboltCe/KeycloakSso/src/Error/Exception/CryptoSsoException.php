<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Error\Exception;

use RuntimeException;

final class CryptoSsoException extends RuntimeException
{
    /**
     * Construct a public-safe cryptographic SSO exception.
     */
    public function __construct(private readonly string $reason)
    {
        parent::__construct('The cryptographic SSO operation failed.');
    }

    /**
     * Return the non-sensitive internal failure category.
     */
    public function reasonCode(): string
    {
        return $this->reason;
    }
}
