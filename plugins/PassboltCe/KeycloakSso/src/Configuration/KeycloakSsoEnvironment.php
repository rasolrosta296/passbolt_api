<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Configuration;

use RuntimeException;

final class KeycloakSsoEnvironment
{
    public const ENABLED = 'KEYCLOAK_SSO_ENABLED';
    public const ISSUER = 'KEYCLOAK_SSO_ISSUER';
    public const CLIENT_ID = 'KEYCLOAK_SSO_CLIENT_ID';
    public const CLIENT_SECRET = 'KEYCLOAK_SSO_CLIENT_SECRET';
    public const REDIRECT_URI = 'KEYCLOAK_SSO_REDIRECT_URI';
    public const TRANSACTION_ENCRYPTION_KEY = 'KEYCLOAK_SSO_TRANSACTION_ENCRYPTION_KEY';
    public const PROVISIONING_ENABLED = 'KEYCLOAK_SSO_PROVISIONING_ENABLED';
    public const PROVISIONING_CLIENT_ID = 'KEYCLOAK_SSO_PROVISIONING_CLIENT_ID';
    public const PROVISIONING_CLIENT_SECRET = 'KEYCLOAK_SSO_PROVISIONING_CLIENT_SECRET';
    public const PROVISIONING_ACTOR_USER_ID = 'KEYCLOAK_SSO_PROVISIONING_ACTOR_USER_ID';
    public const PROVISIONING_INITIAL_LOOKBACK_SECONDS = 'KEYCLOAK_SSO_PROVISIONING_INITIAL_LOOKBACK_SECONDS';
    public const PROVISIONING_OVERLAP_SECONDS = 'KEYCLOAK_SSO_PROVISIONING_OVERLAP_SECONDS';
    public const PROVISIONING_BATCH_SIZE = 'KEYCLOAK_SSO_PROVISIONING_BATCH_SIZE';
    public const GROUP_PROVISIONING_ENABLED = 'KEYCLOAK_SSO_GROUP_PROVISIONING_ENABLED';

    /**
     * Return whether the plugin is enabled, rejecting ambiguous boolean values.
     */
    public static function isEnabled(): bool
    {
        $value = env(self::ENABLED, false);
        $enabled = filter_var($value, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
        if ($enabled === null) {
            throw new RuntimeException(self::ENABLED . ' must be a boolean value.');
        }

        return $enabled;
    }
}
