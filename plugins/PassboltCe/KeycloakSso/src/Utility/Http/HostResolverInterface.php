<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Utility\Http;

interface HostResolverInterface
{
    /** @return list<string> */
    public function resolve(string $host): array;
}
