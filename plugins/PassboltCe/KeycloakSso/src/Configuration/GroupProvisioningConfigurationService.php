<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Configuration;

use Passbolt\KeycloakSso\Error\Exception\OidcConfigurationException;

final class GroupProvisioningConfigurationService
{
    /** Return whether the independently gated group-provisioning feature is enabled. */
    public function isEnabled(?array $environment = null): bool
    {
        $value = $environment === null
            ? getenv(KeycloakSsoEnvironment::GROUP_PROVISIONING_ENABLED)
            : ($environment[KeycloakSsoEnvironment::GROUP_PROVISIONING_ENABLED] ?? false);

        return filter_var($value, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE) === true;
    }

    /** Require the independently gated group-provisioning feature. */
    public function assertEnabled(?array $environment = null): void
    {
        if (!$this->isEnabled($environment)) {
            throw new OidcConfigurationException(
                KeycloakSsoEnvironment::GROUP_PROVISIONING_ENABLED . ' must be explicitly enabled.'
            );
        }
    }

    /** Require a second explicit gate before removing managed access. */
    public function reconciliationEnabled(?array $environment = null): bool
    {
        $value = $environment === null
            ? getenv(KeycloakSsoEnvironment::GROUP_RECONCILIATION_ENABLED)
            : ($environment[KeycloakSsoEnvironment::GROUP_RECONCILIATION_ENABLED] ?? false);
        if ($value === false || $value === '') {
            return false;
        }
        $enabled = filter_var($value, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
        if ($enabled === null) {
            throw new OidcConfigurationException(
                KeycloakSsoEnvironment::GROUP_RECONCILIATION_ENABLED . ' must be true or false.'
            );
        }

        return $enabled;
    }
}
