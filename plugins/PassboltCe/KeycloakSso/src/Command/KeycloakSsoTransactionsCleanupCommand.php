<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Command;

use Cake\Command\Command;
use Cake\Console\Arguments;
use Cake\Console\ConsoleIo;
use Passbolt\KeycloakSso\Service\Transaction\CleanupOidcTransactionsService;

final class KeycloakSsoTransactionsCleanupCommand extends Command
{
    /**
     * @inheritDoc
     */
    public static function getDescription(): string
    {
        return 'Erase expired Keycloak OIDC transaction material.';
    }

    /**
     * @inheritDoc
     */
    public function execute(Arguments $args, ConsoleIo $io): ?int
    {
        $result = (new CleanupOidcTransactionsService())->run();
        $io->success(sprintf(
            'OIDC transaction cleanup complete: expired=%d results=%d deleted=%d.',
            $result['expired'],
            $result['results'],
            $result['deleted']
        ));

        return static::CODE_SUCCESS;
    }
}
