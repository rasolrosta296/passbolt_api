<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\Utility;

use Passbolt\KeycloakSso\Model\Dto\OidcCallbackResult;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction;
use Passbolt\KeycloakSso\Service\Oidc\OidcCallbackProcessorInterface;

final class SuccessfulOidcCallbackProcessor implements OidcCallbackProcessorInterface
{
    /**
     * @var array{state: string, binding: string, code: string}|null
     */
    public ?array $received = null;

    public function process(string $state, string $browserBinding, string $code): OidcCallbackResult
    {
        $this->received = ['state' => $state, 'binding' => $browserBinding, 'code' => $code];

        return new OidcCallbackResult(
            str_repeat('r', 43),
            KeycloakSsoTransaction::PURPOSE_IDENTITY_PROOF
        );
    }

    public function failProviderResponse(string $state, string $browserBinding): void
    {
    }
}
