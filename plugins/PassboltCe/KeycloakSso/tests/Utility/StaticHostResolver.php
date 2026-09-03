<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\Utility;

use Passbolt\KeycloakSso\Utility\Http\HostResolverInterface;

final readonly class StaticHostResolver implements HostResolverInterface
{
    /** @param list<string> $addresses Resolved addresses. */
    public function __construct(private array $addresses)
    {
    }

    /** @return list<string> */
    public function resolve(string $host): array
    {
        return $this->addresses;
    }
}
