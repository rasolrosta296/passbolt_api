<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Command;

use Cake\Command\Command;
use Cake\Console\Arguments;
use Cake\Console\ConsoleIo;
use Cake\Console\ConsoleOptionParser;
use Passbolt\KeycloakSso\Configuration\OidcConfigurationService;
use Passbolt\KeycloakSso\Configuration\ProvisioningConfigurationService;
use Passbolt\KeycloakSso\Service\Audit\ProvisioningAuditService;
use Passbolt\KeycloakSso\Service\Oidc\OidcDiscoveryService;
use Passbolt\KeycloakSso\Service\Oidc\OidcMetadataCache;
use Passbolt\KeycloakSso\Service\Provisioning\KeycloakProvisioningApiService;
use Passbolt\KeycloakSso\Service\Provisioning\ProvisioningSyncService;
use Passbolt\KeycloakSso\Service\Provisioning\ProvisionKeycloakUserService;
use Passbolt\KeycloakSso\Utility\Http\SafeOidcHttpClient;
use Throwable;

final class KeycloakSsoProvisionUsersCommand extends Command
{
    /** Return the command description. */
    public static function getDescription(): string
    {
        return 'Provision invited Passbolt users from saved Keycloak administrator events.';
    }

    /** Add the non-mutating preview option. */
    public function buildOptionParser(ConsoleOptionParser $parser): ConsoleOptionParser
    {
        return parent::buildOptionParser($parser)->addOption('dry-run', [
            'boolean' => true,
            'default' => false,
            'help' => 'Validate eligible events without persisting users or checkpoints.',
        ]);
    }

    /** Run one bounded synchronization pass. */
    public function execute(Arguments $args, ConsoleIo $io): ?int
    {
        try {
            $oidc = (new OidcConfigurationService())->load();
            $provisioning = (new ProvisioningConfigurationService())->load();
            $http = new SafeOidcHttpClient($oidc);
            $discovery = (new OidcDiscoveryService($oidc, $http, new OidcMetadataCache()))->get();
            $api = new KeycloakProvisioningApiService($provisioning, $discovery, $http);
            $provisioner = new ProvisionKeycloakUserService(
                $provisioning,
                $api,
                new ProvisioningAuditService()
            );
            $counts = (new ProvisioningSyncService($provisioning, $api, $provisioner))
                ->run((bool)$args->getOption('dry-run'));
        } catch (Throwable) {
            $io->err('Keycloak user provisioning failed. Review sanitized server logs and configuration.');

            return static::CODE_ERROR;
        }

        $summary = sprintf(
            'Keycloak user provisioning complete: provisioned=%d would_provision=%d skipped=%d ' .
            'collisions=%d duplicates=%d in_progress=%d failed=%d.',
            $counts[ProvisionKeycloakUserService::OUTCOME_PROVISIONED],
            $counts[ProvisionKeycloakUserService::OUTCOME_WOULD_PROVISION],
            $counts[ProvisionKeycloakUserService::OUTCOME_SKIPPED],
            $counts[ProvisionKeycloakUserService::OUTCOME_COLLISION],
            $counts[ProvisionKeycloakUserService::OUTCOME_DUPLICATE],
            $counts[ProvisionKeycloakUserService::OUTCOME_IN_PROGRESS],
            $counts[ProvisionKeycloakUserService::OUTCOME_FAILED]
        );
        if (
            $counts[ProvisionKeycloakUserService::OUTCOME_COLLISION] > 0 ||
            $counts[ProvisionKeycloakUserService::OUTCOME_FAILED] > 0
        ) {
            $io->err($summary);

            return static::CODE_ERROR;
        }
        $io->success($summary);

        return static::CODE_SUCCESS;
    }
}
