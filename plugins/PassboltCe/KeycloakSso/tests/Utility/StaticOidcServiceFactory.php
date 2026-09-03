<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\Utility;

use Passbolt\KeycloakSso\Service\Oidc\AuthorizationRequestProviderInterface;
use Passbolt\KeycloakSso\Service\Oidc\OidcCallbackProcessorInterface;
use Passbolt\KeycloakSso\Service\Oidc\OidcResultConsumerInterface;
use Passbolt\KeycloakSso\Service\Oidc\OidcServiceFactoryInterface;

final readonly class StaticOidcServiceFactory implements OidcServiceFactoryInterface
{
    public function __construct(
        private AuthorizationRequestProviderInterface $authorization,
        private OidcCallbackProcessorInterface $callback,
        private OidcResultConsumerInterface $results,
    ) {
    }

    public function authorizationRequest(): AuthorizationRequestProviderInterface
    {
        return $this->authorization;
    }

    public function callback(): OidcCallbackProcessorInterface
    {
        return $this->callback;
    }

    public function transactions(): OidcResultConsumerInterface
    {
        return $this->results;
    }
}
