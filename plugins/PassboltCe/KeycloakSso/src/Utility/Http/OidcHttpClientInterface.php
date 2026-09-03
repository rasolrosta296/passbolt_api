<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Utility\Http;

use SensitiveParameter;

interface OidcHttpClientInterface
{
    /**
     * @param array<string, string> $form
     * @return array<string, mixed>
     */
    public function requestJson(string $method, string $url, #[SensitiveParameter]
    array $form = []): array;
}
