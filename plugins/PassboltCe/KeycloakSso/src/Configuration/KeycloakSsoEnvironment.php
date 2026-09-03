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
