<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Oidc;

use Passbolt\KeycloakSso\Model\Dto\OidcCallbackResult;

interface OidcCallbackProcessorInterface
{
    /**
     * Validate and consume a successful callback.
     */
    public function process(
        string $state,
        string $browserBinding,
        string $code
    ): OidcCallbackResult;

    /**
     * Consume a valid transaction when the provider reports an error.
     */
    public function failProviderResponse(string $state, string $browserBinding): void;
}
