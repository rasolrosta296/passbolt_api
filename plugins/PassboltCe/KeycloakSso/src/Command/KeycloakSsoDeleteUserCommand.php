<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Command;

use App\Service\Resources\ResourcesExpireResourcesServiceInterface;
use Cake\Command\Command;
use Cake\Console\Arguments;
use Cake\Console\CommandFactoryInterface;
use Cake\Console\ConsoleIo;
use Cake\Console\ConsoleOptionParser;
use Passbolt\KeycloakSso\Configuration\DeprovisioningConfigurationService;
use Passbolt\KeycloakSso\Configuration\OidcConfigurationService;
use Passbolt\KeycloakSso\Configuration\ProvisioningConfigurationService;
use Passbolt\KeycloakSso\Service\Audit\DeprovisioningAuditService;
use Passbolt\KeycloakSso\Service\Oidc\OidcDiscoveryService;
use Passbolt\KeycloakSso\Service\Oidc\OidcMetadataCache;
use Passbolt\KeycloakSso\Service\Provisioning\KeycloakProvisioningApiService;
use Passbolt\KeycloakSso\Service\Provisioning\ProvisionedUserDeletionService;
use Passbolt\KeycloakSso\Utility\Http\SafeOidcHttpClient;
use Throwable;

final class KeycloakSsoDeleteUserCommand extends Command
{
    /** Construct the command with Passbolt's configured resource-expiry policy. */
    public function __construct(
        private readonly ResourcesExpireResourcesServiceInterface $resourcesExpiry,
        ?CommandFactoryInterface $factory = null,
    ) {
        parent::__construct($factory);
    }

    /** Return the command description. */
    public static function getDescription(): string
    {
        return 'Permanently soft-delete one eligible quarantined Keycloak-provisioned user.';
    }

    /** Require an exact user and an explicit destructive confirmation. */
    public function buildOptionParser(ConsoleOptionParser $parser): ConsoleOptionParser
    {
        return parent::buildOptionParser($parser)
            ->addOption('user-id', ['required' => true, 'help' => 'Exact internal Passbolt user UUID.'])
            ->addOption('confirm', [
                'required' => true,
                'help' => 'Must be exactly DELETE to approve the destructive operation.',
            ]);
    }

    /** Run one explicitly approved deletion. */
    public function execute(Arguments $args, ConsoleIo $io): ?int
    {
        $audit = new DeprovisioningAuditService();
        try {
            $oidc = (new OidcConfigurationService())->load();
            $provisioning = (new ProvisioningConfigurationService())->load();
            $lifecycle = (new DeprovisioningConfigurationService())->load();
            $http = new SafeOidcHttpClient($oidc);
            $discovery = (new OidcDiscoveryService($oidc, $http, new OidcMetadataCache()))->get();
            $api = new KeycloakProvisioningApiService($provisioning, $discovery, $http);
            (new ProvisionedUserDeletionService($lifecycle, $api, $this->resourcesExpiry, $audit))->delete(
                (string)$args->getOption('user-id'),
                (string)$args->getOption('confirm')
            );
        } catch (Throwable) {
            $audit->record('failed', 'unexpected', (string)$args->getOption('user-id'));
            $io->err('Keycloak-provisioned user deletion failed. Review sanitized server logs and account ownership.');

            return static::CODE_ERROR;
        }
        $io->success('The quarantined Keycloak-provisioned user was deleted.');

        return static::CODE_SUCCESS;
    }
}
