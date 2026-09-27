<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\Utility;

use Passbolt\KeycloakSso\Utility\Http\OidcHttpClientInterface;

final class RecordingOidcHttpClient implements OidcHttpClientInterface
{
    public string $method = '';
    public string $url = '';
    /**
     * @var array<string, string>
     */
    public array $form = [];
    /**
     * @var array<string, string>
     */
    public array $headers = [];

    /** @param array<string, mixed> $response Response document. */
    public function __construct(private readonly array $response)
    {
    }

    public function requestJson(string $method, string $url, array $form = [], array $headers = []): array
    {
        $this->method = $method;
        $this->url = $url;
        $this->form = $form;
        $this->headers = $headers;

        return $this->response;
    }
}
