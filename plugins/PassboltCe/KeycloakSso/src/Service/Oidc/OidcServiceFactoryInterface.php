<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Oidc;

interface OidcServiceFactoryInterface
{
    /**
     * Build the authorization request service.
     */
    public function authorizationRequest(): AuthorizationRequestProviderInterface;

    /**
     * Build the callback service.
     */
    public function callback(): OidcCallbackProcessorInterface;

    /**
     * Build the result consumer.
     */
    public function transactions(): OidcResultConsumerInterface;
}
