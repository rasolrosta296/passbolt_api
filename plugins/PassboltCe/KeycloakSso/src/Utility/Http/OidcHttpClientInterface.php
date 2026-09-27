<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Utility\Http;

use SensitiveParameter;

interface OidcHttpClientInterface
{
    /**
     * @param array<string, string> $form
     * @param array<string, string> $headers
     * @return array<mixed>
     */
    public function requestJson(string $method, string $url, #[SensitiveParameter]
    array $form = [], #[SensitiveParameter]
    array $headers = []): array;
}
