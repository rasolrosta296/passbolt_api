<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso;

use App\Service\Resources\ResourcesExpireResourcesServiceInterface;
use Cake\Console\CommandCollection;
use Cake\Core\BasePlugin;
use Cake\Core\ContainerInterface;
use Cake\Core\PluginApplicationInterface;
use Passbolt\KeycloakSso\Command\KeycloakSsoDeleteEligibleUsersCommand;
use Passbolt\KeycloakSso\Command\KeycloakSsoDeleteUserCommand;
use Passbolt\KeycloakSso\Command\KeycloakSsoProvisionUsersCommand;
use Passbolt\KeycloakSso\Command\KeycloakSsoReconcileUsersCommand;
use Passbolt\KeycloakSso\Command\KeycloakSsoServerSharesRewrapCommand;
use Passbolt\KeycloakSso\Command\KeycloakSsoSyncGroupsCommand;
use Passbolt\KeycloakSso\Command\KeycloakSsoTransactionsCleanupCommand;
use Passbolt\KeycloakSso\Event\RevokeCryptoEnrollmentsOnGpgkeyChange;
use Passbolt\KeycloakSso\Service\Crypto\CryptoSsoServiceFactory;
use Passbolt\KeycloakSso\Service\Crypto\CryptoSsoServiceFactoryInterface;
use Passbolt\KeycloakSso\Service\Identity\IdentityLinkServiceFactory;
use Passbolt\KeycloakSso\Service\Identity\IdentityLinkServiceFactoryInterface;
use Passbolt\KeycloakSso\Service\Oidc\OidcServiceFactory;
use Passbolt\KeycloakSso\Service\Oidc\OidcServiceFactoryInterface;
use Passbolt\KeycloakSso\Service\Recovery\AccountRecoveryServiceFactory;
use Passbolt\KeycloakSso\Service\Recovery\AccountRecoveryServiceFactoryInterface;

final class KeycloakSsoPlugin extends BasePlugin
{
    /** @inheritDoc */
    public function console(CommandCollection $commands): CommandCollection
    {
        $commands->add('keycloak_sso_provision_users', KeycloakSsoProvisionUsersCommand::class);
        $commands->add('keycloak_sso_reconcile_users', KeycloakSsoReconcileUsersCommand::class);
        $commands->add('keycloak_sso_delete_user', KeycloakSsoDeleteUserCommand::class);
        $commands->add('keycloak_sso_delete_eligible_users', KeycloakSsoDeleteEligibleUsersCommand::class);
        $commands->add('keycloak_sso_server_shares_rewrap', KeycloakSsoServerSharesRewrapCommand::class);
        $commands->add('keycloak_sso_sync_groups', KeycloakSsoSyncGroupsCommand::class);
        $commands->add('keycloak_sso_transactions_cleanup', KeycloakSsoTransactionsCleanupCommand::class);

        return $commands;
    }

    /** @inheritDoc */
    public function bootstrap(PluginApplicationInterface $app): void
    {
        parent::bootstrap($app);
        $app->getEventManager()->on(new RevokeCryptoEnrollmentsOnGpgkeyChange());
    }

    /**
     * Register the plugin's isolated service factory.
     */
    public function services(ContainerInterface $container): void
    {
        $container->add(OidcServiceFactoryInterface::class)->setConcrete(OidcServiceFactory::class);
        $container->add(IdentityLinkServiceFactoryInterface::class)->setConcrete(IdentityLinkServiceFactory::class);
        $container->add(CryptoSsoServiceFactoryInterface::class)->setConcrete(CryptoSsoServiceFactory::class);
        $container->add(AccountRecoveryServiceFactoryInterface::class)
            ->setConcrete(AccountRecoveryServiceFactory::class);
        $container->add(KeycloakSsoReconcileUsersCommand::class)
            ->addArgument(ResourcesExpireResourcesServiceInterface::class);
        $container->add(KeycloakSsoDeleteUserCommand::class)
            ->addArgument(ResourcesExpireResourcesServiceInterface::class);
        $container->add(KeycloakSsoDeleteEligibleUsersCommand::class)
            ->addArgument(ResourcesExpireResourcesServiceInterface::class);
        $container->add(KeycloakSsoSyncGroupsCommand::class)
            ->addArgument(ResourcesExpireResourcesServiceInterface::class);
    }
}
