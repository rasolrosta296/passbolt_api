<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\Utility;

use Passbolt\KeycloakSso\Utility\Http\OidcHttpClientInterface;

final class QueuedOidcHttpClient implements OidcHttpClientInterface
{
    /**
     * @var list<array{method: string, url: string, form: array<string, string>, headers: array<string, string>}>
     */
    public array $requests = [];

    /** @param list<array<mixed>> $responses Responses returned in order. */
    public function __construct(private array $responses)
    {
    }

    /**
     * @param array<string, string> $form Request form.
     * @param array<string, string> $headers Request headers.
     * @return array<mixed>
     */
    public function requestJson(string $method, string $url, array $form = [], array $headers = []): array
    {
        $this->requests[] = compact('method', 'url', 'form', 'headers');

        return array_shift($this->responses) ?? [];
    }
}
