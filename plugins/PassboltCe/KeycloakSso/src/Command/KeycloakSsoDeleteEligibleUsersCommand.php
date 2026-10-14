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

final class KeycloakSsoDeleteEligibleUsersCommand extends Command
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
        return 'Soft-delete one bounded page of eligible absent Keycloak-provisioned users.';
    }

    /** Add the non-mutating automatic-deletion preview option. */
    public function buildOptionParser(ConsoleOptionParser $parser): ConsoleOptionParser
    {
        return parent::buildOptionParser($parser)->addOption('dry-run', [
            'boolean' => true,
            'default' => false,
            'help' => 'Validate eligible deleted identities without changing Passbolt users.',
        ]);
    }

    /** Run one bounded automatic-deletion pass. */
    public function execute(Arguments $args, ConsoleIo $io): ?int
    {
        try {
            $lifecycle = (new DeprovisioningConfigurationService())->load();
            if (!$lifecycle->automaticDeletionEnabled) {
                $io->success($this->summary([
                    ProvisionedUserDeletionService::OUTCOME_WOULD_DELETE => 0,
                    ProvisionedUserDeletionService::OUTCOME_DELETED => 0,
                    ProvisionedUserDeletionService::OUTCOME_FAILED => 0,
                ]));

                return static::CODE_SUCCESS;
            }
            $oidc = (new OidcConfigurationService())->load();
            $provisioning = (new ProvisioningConfigurationService())->load();
            $http = new SafeOidcHttpClient($oidc);
            $discovery = (new OidcDiscoveryService($oidc, $http, new OidcMetadataCache()))->get();
            $api = new KeycloakProvisioningApiService($provisioning, $discovery, $http);
            $counts = (new ProvisionedUserDeletionService(
                $lifecycle,
                $api,
                $this->resourcesExpiry,
                new DeprovisioningAuditService()
            ))->deleteEligible((bool)$args->getOption('dry-run'));
        } catch (Throwable) {
            $io->err('Automatic Keycloak user deletion failed. Review sanitized server logs.');

            return static::CODE_ERROR;
        }
        $summary = $this->summary($counts);
        if ($counts[ProvisionedUserDeletionService::OUTCOME_FAILED] > 0) {
            $io->err($summary);

            return static::CODE_ERROR;
        }
        $io->success($summary);

        return static::CODE_SUCCESS;
    }

    /** @param array{would_delete: int, deleted: int, failed: int} $counts */
    private function summary(array $counts): string
    {
        return sprintf(
            'Automatic Keycloak user deletion complete: would_delete=%d deleted=%d failed=%d.',
            $counts[ProvisionedUserDeletionService::OUTCOME_WOULD_DELETE],
            $counts[ProvisionedUserDeletionService::OUTCOME_DELETED],
            $counts[ProvisionedUserDeletionService::OUTCOME_FAILED]
        );
    }
}
