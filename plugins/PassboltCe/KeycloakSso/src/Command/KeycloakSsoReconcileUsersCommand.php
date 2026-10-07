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
use Passbolt\KeycloakSso\Service\Provisioning\ManagedGroupAccessRemovalService;
use Passbolt\KeycloakSso\Service\Provisioning\ProvisionedUserLifecycleService;
use Passbolt\KeycloakSso\Utility\Http\SafeOidcHttpClient;
use Throwable;

final class KeycloakSsoReconcileUsersCommand extends Command
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
        return 'Reconcile Keycloak-provisioned Passbolt user lifecycle state.';
    }

    /** Add the non-mutating lifecycle preview option. */
    public function buildOptionParser(ConsoleOptionParser $parser): ConsoleOptionParser
    {
        return parent::buildOptionParser($parser)->addOption('dry-run', [
            'boolean' => true,
            'default' => false,
            'help' => 'Inspect lifecycle changes without disabling users or revoking access.',
        ]);
    }

    /** Run one bounded authoritative reconciliation pass. */
    public function execute(Arguments $args, ConsoleIo $io): ?int
    {
        try {
            $oidc = (new OidcConfigurationService())->load();
            $provisioning = (new ProvisioningConfigurationService())->load();
            $lifecycle = (new DeprovisioningConfigurationService())->load();
            $http = new SafeOidcHttpClient($oidc);
            $discovery = (new OidcDiscoveryService($oidc, $http, new OidcMetadataCache()))->get();
            $api = new KeycloakProvisioningApiService($provisioning, $discovery, $http);
            $counts = (new ProvisionedUserLifecycleService(
                $lifecycle,
                $api,
                new ManagedGroupAccessRemovalService($this->resourcesExpiry),
                $this->resourcesExpiry,
                new DeprovisioningAuditService()
            ))->run((bool)$args->getOption('dry-run'));
        } catch (Throwable) {
            $io->err('Keycloak user lifecycle reconciliation failed. Review sanitized server logs.');

            return static::CODE_ERROR;
        }
        $summary = sprintf(
            'Keycloak user lifecycle reconciliation complete: active=%d would_deprovision=%d ' .
            'deprovisioned=%d in_progress=%d reactivation_required=%d failed=%d.',
            $counts[ProvisionedUserLifecycleService::OUTCOME_ACTIVE],
            $counts[ProvisionedUserLifecycleService::OUTCOME_WOULD_DEPROVISION],
            $counts[ProvisionedUserLifecycleService::OUTCOME_DEPROVISIONED],
            $counts[ProvisionedUserLifecycleService::OUTCOME_IN_PROGRESS],
            $counts[ProvisionedUserLifecycleService::OUTCOME_REACTIVATION_REQUIRED],
            $counts[ProvisionedUserLifecycleService::OUTCOME_FAILED]
        );
        if ($counts[ProvisionedUserLifecycleService::OUTCOME_FAILED] > 0) {
            $io->err($summary);

            return static::CODE_ERROR;
        }
        $io->success($summary);

        return static::CODE_SUCCESS;
    }
}
