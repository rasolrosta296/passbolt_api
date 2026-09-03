<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\Utility;

use Passbolt\KeycloakSso\Utility\Http\OidcHttpClientInterface;

final class RecordingOidcHttpClient implements OidcHttpClientInterface
{
    public string $method = '';
    /**
     * @var array<string, string>
     */
    public array $form = [];

    /** @param array<string, mixed> $response Response document. */
    public function __construct(private readonly array $response)
    {
    }

    public function requestJson(string $method, string $url, array $form = []): array
    {
        $this->method = $method;
        $this->form = $form;

        return $this->response;
    }
}
