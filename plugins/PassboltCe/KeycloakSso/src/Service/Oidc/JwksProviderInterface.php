<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Oidc;

interface JwksProviderInterface
{
    /** @return array{keys: list<array<string, mixed>>} */
    public function get(bool $forceRefresh = false): array;
}
