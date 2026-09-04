<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Command;

use Cake\Command\Command;
use Cake\Console\Arguments;
use Cake\Console\ConsoleIo;
use Passbolt\KeycloakSso\Configuration\CryptoConfigurationService;
use Passbolt\KeycloakSso\Cryptography\ServerShareProtector;
use Passbolt\KeycloakSso\Service\Crypto\RewrapServerSharesService;

final class KeycloakSsoServerSharesRewrapCommand extends Command
{
    /**
     * Return the command description.
     */
    public static function getDescription(): string
    {
        return 'Rewrap active Keycloak SSO server shares under the configured active KEK.';
    }

    /**
     * Rewrap all active shares under the configured active KEK.
     */
    public function execute(Arguments $args, ConsoleIo $io): ?int
    {
        $configuration = (new CryptoConfigurationService())->load();
        $count = (new RewrapServerSharesService(
            $configuration,
            new ServerShareProtector($configuration)
        ))->rewrap();
        $io->success(sprintf('Rewrapped %d Keycloak SSO server share(s).', $count));

        return static::CODE_SUCCESS;
    }
}
