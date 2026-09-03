<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\Utility;

use Passbolt\KeycloakSso\Error\Exception\OidcNetworkException;
use Passbolt\KeycloakSso\Utility\Http\OidcHttpClientInterface;

final class FailingOidcHttpClient implements OidcHttpClientInterface
{
    public function requestJson(string $method, string $url, array $form = []): array
    {
        throw new OidcNetworkException('The OIDC provider request failed.');
    }
}
