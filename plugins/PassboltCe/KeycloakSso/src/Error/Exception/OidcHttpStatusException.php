<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Error\Exception;

final class OidcHttpStatusException extends OidcNetworkException
{
    /** Construct a body-free HTTP failure safe for exact status handling. */
    public function __construct(public readonly int $status)
    {
        parent::__construct('The OIDC provider returned an unsuccessful status.');
    }
}
