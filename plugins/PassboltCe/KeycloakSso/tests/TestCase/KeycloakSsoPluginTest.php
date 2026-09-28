<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase;

use Cake\Console\CommandCollection;
use Cake\TestSuite\TestCase;
use Passbolt\KeycloakSso\Command\KeycloakSsoProvisionUsersCommand;
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
}
