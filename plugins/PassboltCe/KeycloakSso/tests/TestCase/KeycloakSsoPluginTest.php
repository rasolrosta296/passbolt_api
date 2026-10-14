<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase;

use App\Service\Resources\ResourcesExpireResourcesFallbackServiceService;
use App\Service\Resources\ResourcesExpireResourcesServiceInterface;
use Cake\Console\CommandCollection;
use Cake\Core\Container;
use Cake\TestSuite\TestCase;
use Passbolt\KeycloakSso\Command\KeycloakSsoDeleteEligibleUsersCommand;
use Passbolt\KeycloakSso\Command\KeycloakSsoDeleteUserCommand;
use Passbolt\KeycloakSso\Command\KeycloakSsoProvisionUsersCommand;
use Passbolt\KeycloakSso\Command\KeycloakSsoReconcileUsersCommand;
use Passbolt\KeycloakSso\Command\KeycloakSsoServerSharesRewrapCommand;
use Passbolt\KeycloakSso\Command\KeycloakSsoSyncGroupsCommand;
use Passbolt\KeycloakSso\Command\KeycloakSsoTransactionsCleanupCommand;
use Passbolt\KeycloakSso\KeycloakSsoPlugin;

final class KeycloakSsoPluginTest extends TestCase
{
    public function testRegistersOperationalConsoleCommands(): void
    {
        $commands = (new KeycloakSsoPlugin())->console(new CommandCollection());

        $this->assertSame(
            KeycloakSsoProvisionUsersCommand::class,
            $commands->get('keycloak_sso_provision_users')
        );
        $this->assertSame(
            KeycloakSsoReconcileUsersCommand::class,
            $commands->get('keycloak_sso_reconcile_users')
        );
        $this->assertSame(
            KeycloakSsoDeleteUserCommand::class,
            $commands->get('keycloak_sso_delete_user')
        );
        $this->assertSame(
            KeycloakSsoDeleteEligibleUsersCommand::class,
            $commands->get('keycloak_sso_delete_eligible_users')
        );
        $this->assertSame(
            KeycloakSsoServerSharesRewrapCommand::class,
            $commands->get('keycloak_sso_server_shares_rewrap')
        );
        $this->assertSame(
            KeycloakSsoTransactionsCleanupCommand::class,
            $commands->get('keycloak_sso_transactions_cleanup')
        );
        $this->assertSame(
            KeycloakSsoSyncGroupsCommand::class,
            $commands->get('keycloak_sso_sync_groups')
        );
    }

    public function testLifecycleCommandsUseConfiguredResourceExpiryService(): void
    {
        $container = new Container();
        $container->add(
            ResourcesExpireResourcesServiceInterface::class,
            ResourcesExpireResourcesFallbackServiceService::class
        );
        (new KeycloakSsoPlugin())->services($container);

        $this->assertInstanceOf(
            KeycloakSsoReconcileUsersCommand::class,
            $container->get(KeycloakSsoReconcileUsersCommand::class)
        );
        $this->assertInstanceOf(
            KeycloakSsoDeleteUserCommand::class,
            $container->get(KeycloakSsoDeleteUserCommand::class)
        );
        $this->assertInstanceOf(
            KeycloakSsoDeleteEligibleUsersCommand::class,
            $container->get(KeycloakSsoDeleteEligibleUsersCommand::class)
        );
        $this->assertInstanceOf(
            KeycloakSsoSyncGroupsCommand::class,
            $container->get(KeycloakSsoSyncGroupsCommand::class)
        );
    }
}
