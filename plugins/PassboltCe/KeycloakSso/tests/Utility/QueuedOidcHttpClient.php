<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\Utility;

use Passbolt\KeycloakSso\Utility\Http\OidcHttpClientInterface;

final class QueuedOidcHttpClient implements OidcHttpClientInterface
{
    /** @param list<array<string, mixed>> $responses Responses returned in order. */
    public function __construct(private array $responses)
    {
    }

    /**
     * @param array<string, string> $form Request form.
     * @return array<string, mixed>
     */
    public function requestJson(string $method, string $url, array $form = []): array
    {
        return array_shift($this->responses) ?? [];
    }
}
