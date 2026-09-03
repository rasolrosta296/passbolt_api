<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\Utility;

use Passbolt\KeycloakSso\Service\Oidc\JwksProviderInterface;

final class StaticJwksProvider implements JwksProviderInterface
{
    public int $normalCalls = 0;
    public int $refreshCalls = 0;

    /**
     * @param array{keys: list<array<string, mixed>>} $jwks Initial JWKS.
     * @param array{keys: list<array<string, mixed>>}|null $refreshedJwks Refreshed JWKS.
     */
    public function __construct(private array $jwks, private readonly ?array $refreshedJwks = null)
    {
    }

    public function get(bool $forceRefresh = false): array
    {
        if ($forceRefresh) {
            $this->refreshCalls++;

            return $this->refreshedJwks ?? $this->jwks;
        }
        $this->normalCalls++;

        return $this->jwks;
    }
}
