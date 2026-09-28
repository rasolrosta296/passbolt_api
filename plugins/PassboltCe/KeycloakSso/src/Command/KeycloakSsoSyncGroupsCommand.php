<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Command;

use Cake\Command\Command;
use Cake\Console\Arguments;
use Cake\Console\ConsoleIo;
use Cake\Console\ConsoleOptionParser;
use Passbolt\KeycloakSso\Configuration\GroupProvisioningConfigurationService;
use Passbolt\KeycloakSso\Configuration\OidcConfigurationService;
use Passbolt\KeycloakSso\Configuration\ProvisioningConfigurationService;
use Passbolt\KeycloakSso\Service\Audit\GroupProvisioningAuditService;
use Passbolt\KeycloakSso\Service\Oidc\OidcDiscoveryService;
use Passbolt\KeycloakSso\Service\Oidc\OidcMetadataCache;
use Passbolt\KeycloakSso\Service\Provisioning\KeycloakProvisioningApiService;
use Passbolt\KeycloakSso\Service\Provisioning\ProvisioningGroupSyncService;
use Passbolt\KeycloakSso\Utility\Http\SafeOidcHttpClient;
use Throwable;

final class KeycloakSsoSyncGroupsCommand extends Command
{
    /** Return the command description. */
    public static function getDescription(): string
    {
        return 'Synchronize Keycloak groups and cryptographically safe Passbolt memberships.';
    }

    /** Add the non-mutating preview option. */
    public function buildOptionParser(ConsoleOptionParser $parser): ConsoleOptionParser
    {
        return parent::buildOptionParser($parser)->addOption('dry-run', [
            'boolean' => true,
            'default' => false,
            'help' => 'Validate group synchronization without persisting changes.',
        ]);
    }

    /** Run one bounded synchronization pass. */
    public function execute(Arguments $args, ConsoleIo $io): ?int
    {
        try {
            (new GroupProvisioningConfigurationService())->assertEnabled();
            $oidc = (new OidcConfigurationService())->load();
            $provisioning = (new ProvisioningConfigurationService())->load();
            $http = new SafeOidcHttpClient($oidc);
            $discovery = (new OidcDiscoveryService($oidc, $http, new OidcMetadataCache()))->get();
            $api = new KeycloakProvisioningApiService($provisioning, $discovery, $http);
            $counts = (new ProvisioningGroupSyncService(
                $provisioning,
                $api,
                new GroupProvisioningAuditService()
            ))
                ->run((bool)$args->getOption('dry-run'));
        } catch (Throwable) {
            $io->err('Keycloak group synchronization failed. Review sanitized server logs and configuration.');

            return static::CODE_ERROR;
        }

        $summary = sprintf(
            'Keycloak group synchronization complete: groups_created=%d groups_would_create=%d ' .
            'memberships_added=%d memberships_would_add=%d pending_activation=%d pending_crypto=%d ' .
            'existing=%d skipped=%d failed=%d.',
            $counts[ProvisioningGroupSyncService::OUTCOME_GROUP_CREATED],
            $counts[ProvisioningGroupSyncService::OUTCOME_GROUP_WOULD_CREATE],
            $counts[ProvisioningGroupSyncService::OUTCOME_MEMBERSHIP_ADDED],
            $counts[ProvisioningGroupSyncService::OUTCOME_MEMBERSHIP_WOULD_ADD],
            $counts[ProvisioningGroupSyncService::OUTCOME_PENDING_ACTIVATION],
            $counts[ProvisioningGroupSyncService::OUTCOME_PENDING_CRYPTO],
            $counts[ProvisioningGroupSyncService::OUTCOME_EXISTING],
            $counts[ProvisioningGroupSyncService::OUTCOME_SKIPPED],
            $counts[ProvisioningGroupSyncService::OUTCOME_FAILED]
        );
        if ($counts[ProvisioningGroupSyncService::OUTCOME_FAILED] > 0) {
            $io->err($summary);

            return static::CODE_ERROR;
        }
        $io->success($summary);

        return static::CODE_SUCCESS;
    }
}
