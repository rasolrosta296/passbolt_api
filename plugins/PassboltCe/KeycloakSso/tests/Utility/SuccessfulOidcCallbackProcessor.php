<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\Utility;

use Passbolt\KeycloakSso\Service\Oidc\OidcCallbackProcessorInterface;

final class SuccessfulOidcCallbackProcessor implements OidcCallbackProcessorInterface
{
    /**
     * @var array{state: string, binding: string, code: string}|null
     */
    public ?array $received = null;

    public function process(string $state, string $browserBinding, string $code): string
    {
        $this->received = ['state' => $state, 'binding' => $browserBinding, 'code' => $code];

        return str_repeat('r', 43);
    }

    public function failProviderResponse(string $state, string $browserBinding): void
    {
    }
}
