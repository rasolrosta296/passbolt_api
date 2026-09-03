<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Oidc;

interface OidcCallbackProcessorInterface
{
    /**
     * Validate and consume a successful callback.
     */
    public function process(string $state, string $browserBinding, string $code): string;

    /**
     * Consume a valid transaction when the provider reports an error.
     */
    public function failProviderResponse(string $state, string $browserBinding): void;
}
