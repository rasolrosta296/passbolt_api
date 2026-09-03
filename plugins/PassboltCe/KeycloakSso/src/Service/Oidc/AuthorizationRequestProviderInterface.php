<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Oidc;

use Passbolt\KeycloakSso\Model\Dto\OidcAuthorizationRequest;

interface AuthorizationRequestProviderInterface
{
    /**
     * Create a browser-bound OIDC authorization request.
     */
    public function create(): OidcAuthorizationRequest;
}
