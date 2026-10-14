<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Configuration;

use Passbolt\KeycloakSso\Error\Exception\OidcConfigurationException;
use Passbolt\KeycloakSso\Model\Dto\DeprovisioningConfigurationDto;

final class DeprovisioningConfigurationService
{
    /** Load the independently gated destructive lifecycle policy. */
    public function load(?array $environment = null): DeprovisioningConfigurationDto
    {
        $read = static function (string $name) use ($environment): string|false {
            return $environment === null ? getenv($name) : ($environment[$name] ?? false);
        };
        $enabled = filter_var(
            $read(KeycloakSsoEnvironment::DEPROVISIONING_ENABLED),
            FILTER_VALIDATE_BOOLEAN,
            FILTER_NULL_ON_FAILURE
        );
        if ($enabled !== true) {
            throw new OidcConfigurationException('Keycloak user deprovisioning is not explicitly enabled.');
        }
        $provisioning = (new ProvisioningConfigurationService())->load($environment);
        $rawGrace = $read(KeycloakSsoEnvironment::DEPROVISIONING_GRACE_SECONDS);
        $grace = DeprovisioningConfigurationDto::DEFAULT_GRACE_SECONDS;
        if ($rawGrace !== false && $rawGrace !== '') {
            if (!ctype_digit($rawGrace)) {
                throw new OidcConfigurationException(
                    KeycloakSsoEnvironment::DEPROVISIONING_GRACE_SECONDS . ' must be an integer.'
                );
            }
            $grace = (int)$rawGrace;
        }
        if (
            $grace < DeprovisioningConfigurationDto::MIN_GRACE_SECONDS ||
            $grace > DeprovisioningConfigurationDto::MAX_GRACE_SECONDS
        ) {
            throw new OidcConfigurationException(sprintf(
                '%s must be between %d and %d.',
                KeycloakSsoEnvironment::DEPROVISIONING_GRACE_SECONDS,
                DeprovisioningConfigurationDto::MIN_GRACE_SECONDS,
                DeprovisioningConfigurationDto::MAX_GRACE_SECONDS
            ));
        }
        $rawReactivation = $read(KeycloakSsoEnvironment::REACTIVATION_ENABLED);
        $reactivationEnabled = $rawReactivation === false || $rawReactivation === ''
            ? false
            : filter_var($rawReactivation, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
        if ($reactivationEnabled === null) {
            throw new OidcConfigurationException(
                KeycloakSsoEnvironment::REACTIVATION_ENABLED . ' must be a boolean value.'
            );
        }
        $rawAutomaticDeletion = $read(KeycloakSsoEnvironment::AUTOMATIC_DELETION_ENABLED);
        $automaticDeletionEnabled = $rawAutomaticDeletion === false || $rawAutomaticDeletion === ''
            ? false
            : filter_var($rawAutomaticDeletion, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
        if ($automaticDeletionEnabled === null) {
            throw new OidcConfigurationException(
                KeycloakSsoEnvironment::AUTOMATIC_DELETION_ENABLED . ' must be a boolean value.'
            );
        }

        return new DeprovisioningConfigurationDto(
            $provisioning->issuer,
            $provisioning->actorUserId,
            $provisioning->batchSize,
            $grace,
            $reactivationEnabled,
            $automaticDeletionEnabled
        );
    }
}
