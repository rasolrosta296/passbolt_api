<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Configuration;

use Cake\Core\Configure;
use Passbolt\KeycloakSso\Error\Exception\OidcConfigurationException;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;

final class OidcConfigurationService
{
    /**
     * @param array<string, string|false>|null $environment Test override; production reads process environment.
     */
    public function load(?array $environment = null): OidcConfigurationDto
    {
        $read = static function (string $name) use ($environment): string|false {
            return $environment === null ? getenv($name) : ($environment[$name] ?? false);
        };

        $enabledValue = $read(KeycloakSsoEnvironment::ENABLED);
        $enabled = filter_var($enabledValue, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
        if ($enabled !== true) {
            throw new OidcConfigurationException('Keycloak SSO is not explicitly enabled.');
        }

        $issuer = $this->required($read(KeycloakSsoEnvironment::ISSUER), KeycloakSsoEnvironment::ISSUER);
        $clientId = $this->required($read(KeycloakSsoEnvironment::CLIENT_ID), KeycloakSsoEnvironment::CLIENT_ID);
        $clientSecret = $this->required(
            $read(KeycloakSsoEnvironment::CLIENT_SECRET),
            KeycloakSsoEnvironment::CLIENT_SECRET
        );
        $redirectUri = $this->required(
            $read(KeycloakSsoEnvironment::REDIRECT_URI),
            KeycloakSsoEnvironment::REDIRECT_URI
        );
        $encodedEncryptionKey = $this->required(
            $read(KeycloakSsoEnvironment::TRANSACTION_ENCRYPTION_KEY),
            KeycloakSsoEnvironment::TRANSACTION_ENCRYPTION_KEY
        );

        $this->assertIssuer($issuer);
        $this->assertClientId($clientId);
        $this->assertRedirectUri($redirectUri);
        $encryptionKey = base64_decode($encodedEncryptionKey, true);
        if ($encryptionKey === false || strlen($encryptionKey) !== 32) {
            throw new OidcConfigurationException(
                KeycloakSsoEnvironment::TRANSACTION_ENCRYPTION_KEY . ' must be base64 encoding of exactly 32 bytes.'
            );
        }

        return new OidcConfigurationDto($issuer, $clientId, $clientSecret, $redirectUri, $encryptionKey);
    }

    private function required(string|false $value, string $name): string
    {
        if (!is_string($value) || $value === '' || trim($value) !== $value || preg_match('/[\x00-\x1F\x7F]/', $value)) {
            throw new OidcConfigurationException($name . ' is required and must not contain whitespace or controls.');
        }

        return $value;
    }

    private function assertIssuer(string $issuer): void
    {
        $parts = parse_url($issuer);
        if (
            $parts === false || ($parts['scheme'] ?? null) !== 'https' || empty($parts['host']) ||
            isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment']) ||
            str_ends_with($issuer, '/') || !str_contains($parts['path'] ?? '', '/realms/')
        ) {
            throw new OidcConfigurationException(
                KeycloakSsoEnvironment::ISSUER . ' must be an exact HTTPS Keycloak realm issuer without a trailing slash.'
            );
        }
    }

    private function assertClientId(string $clientId): void
    {
        if (strlen($clientId) > 255) {
            throw new OidcConfigurationException(KeycloakSsoEnvironment::CLIENT_ID . ' is too long.');
        }
    }

    private function assertRedirectUri(string $redirectUri): void
    {
        $parts = parse_url($redirectUri);
        if (
            $parts === false || ($parts['scheme'] ?? null) !== 'https' || empty($parts['host']) ||
            ($parts['path'] ?? '') !== '/auth/keycloak/callback' || isset($parts['user']) || isset($parts['pass']) ||
            isset($parts['query']) || isset($parts['fragment'])
        ) {
            throw new OidcConfigurationException(
                KeycloakSsoEnvironment::REDIRECT_URI . ' must be an exact HTTPS /auth/keycloak/callback URL.'
            );
        }

        $fullBaseUrl = Configure::read('App.fullBaseUrl');
        $enforce = Configure::read('passbolt.security.fullBaseUrlEnforce', false);
        if ($enforce && is_string($fullBaseUrl)) {
            $expected = rtrim($fullBaseUrl, '/') . '/auth/keycloak/callback';
            if (!hash_equals($expected, $redirectUri)) {
                throw new OidcConfigurationException(
                    KeycloakSsoEnvironment::REDIRECT_URI . ' does not match the enforced Passbolt public URL.'
                );
            }
        }
    }
}
