<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso;

use Cake\Core\BasePlugin;
use Cake\Core\ContainerInterface;
use Passbolt\KeycloakSso\Service\Identity\IdentityLinkServiceFactory;
use Passbolt\KeycloakSso\Service\Identity\IdentityLinkServiceFactoryInterface;
use Passbolt\KeycloakSso\Service\Oidc\OidcServiceFactory;
use Passbolt\KeycloakSso\Service\Oidc\OidcServiceFactoryInterface;

final class KeycloakSsoPlugin extends BasePlugin
{
    /**
     * Register the plugin's isolated service factory.
     */
    public function services(ContainerInterface $container): void
    {
        $container->add(OidcServiceFactoryInterface::class)->setConcrete(OidcServiceFactory::class);
        $container->add(IdentityLinkServiceFactoryInterface::class)->setConcrete(IdentityLinkServiceFactory::class);
    }
}
