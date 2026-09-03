<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\Utility;

use Passbolt\KeycloakSso\Model\Dto\OidcAuthorizationRequest;
use Passbolt\KeycloakSso\Service\Oidc\AuthorizationRequestProviderInterface;

final readonly class StaticAuthorizationRequestProvider implements AuthorizationRequestProviderInterface
{
    public function create(): OidcAuthorizationRequest
    {
        return new OidcAuthorizationRequest('https://keyclock.gobaz.ir/authorize', str_repeat('b', 43));
    }
}
