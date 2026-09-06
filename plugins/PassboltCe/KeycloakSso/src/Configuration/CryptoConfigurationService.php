<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Configuration;

use Cake\Core\Configure;
use JsonException;
use Passbolt\KeycloakSso\Error\Exception\OidcConfigurationException;
use Passbolt\KeycloakSso\Model\Dto\CryptoConfigurationDto;
use SensitiveParameter;

final class CryptoConfigurationService
{
    public const RELEASE_ACR = 'KEYCLOAK_SSO_RELEASE_ACR';
    public const RELEASE_AMR = 'KEYCLOAK_SSO_RELEASE_AMR';
    public const ACTIVE_KEK_ID = 'KEYCLOAK_SSO_SERVER_SHARE_ACTIVE_KEY_ID';
    public const KEK_KEYRING = 'KEYCLOAK_SSO_SERVER_SHARE_KEYRING';

    /** @param array<string, string|false>|null $environment */
    public function load(#[SensitiveParameter]
    ?array $environment = null): CryptoConfigurationDto
    {
        $read = static fn (string $name): string|false => $environment === null
            ? getenv($name)
            : ($environment[$name] ?? false);
        $origin = $this->origin();
        $acr = $this->required($read(self::RELEASE_ACR), self::RELEASE_ACR, 255);
        $activeId = $this->required($read(self::ACTIVE_KEK_ID), self::ACTIVE_KEK_ID, 64);
        if (preg_match('/^[a-z0-9._-]+$/D', $activeId) !== 1) {
            throw new OidcConfigurationException(self::ACTIVE_KEK_ID . ' has an invalid format.');
        }
        $keyringJson = $this->required($read(self::KEK_KEYRING), self::KEK_KEYRING, 16_384);
        try {
            $encodedKeys = json_decode($keyringJson, true, 8, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new OidcConfigurationException(self::KEK_KEYRING . ' must be a JSON object.');
        }
        if (
            !is_array($encodedKeys) || array_is_list($encodedKeys) ||
            count($encodedKeys) < 1 || count($encodedKeys) > 16
        ) {
            throw new OidcConfigurationException(self::KEK_KEYRING . ' must contain one to sixteen named keys.');
        }
        $keys = [];
        foreach ($encodedKeys as $id => $encoded) {
            if (!is_string($id) || preg_match('/^[a-z0-9._-]{1,64}$/D', $id) !== 1 || !is_string($encoded)) {
                throw new OidcConfigurationException(self::KEK_KEYRING . ' contains an invalid key entry.');
            }
            $key = base64_decode($encoded, true);
            if ($key === false || strlen($key) !== 32 || !hash_equals(base64_encode($key), $encoded)) {
                throw new OidcConfigurationException(self::KEK_KEYRING . ' keys must be canonical base64 of 32 bytes.');
            }
            $keys[$id] = $key;
        }
        if (!array_key_exists($activeId, $keys)) {
            throw new OidcConfigurationException(self::ACTIVE_KEK_ID . ' is absent from the key ring.');
        }

        return new CryptoConfigurationDto($origin, $acr, $this->amr($read(self::RELEASE_AMR)), $activeId, $keys);
    }

    /**
     * Return the configured canonical public Passbolt origin.
     */
    private function origin(): string
    {
        $base = Configure::read('App.fullBaseUrl');
        if (!is_string($base)) {
            throw new OidcConfigurationException('App.fullBaseUrl must define the public Passbolt origin.');
        }
        $origin = rtrim($base, '/');
        $parts = parse_url($origin);
        if (
            !is_array($parts) || ($parts['scheme'] ?? null) !== 'https' || empty($parts['host']) ||
            isset($parts['user']) || isset($parts['pass']) || isset($parts['path']) ||
            isset($parts['query']) || isset($parts['fragment'])
        ) {
            throw new OidcConfigurationException('App.fullBaseUrl must be a canonical HTTPS origin.');
        }
        $host = $parts['host'];
        $port = $parts['port'] ?? null;
        $labels = explode('.', $host);
        if (strtolower($host) !== $host || count($labels) < 2 || $port === 443) {
            throw new OidcConfigurationException('App.fullBaseUrl must be a canonical HTTPS origin.');
        }
        foreach ($labels as $label) {
            if (preg_match('/^(?!-)[a-z0-9-]{1,63}(?<!-)$/D', $label) !== 1) {
                throw new OidcConfigurationException('App.fullBaseUrl must be a canonical HTTPS origin.');
            }
        }
        $canonical = 'https://' . $host . ($port === null ? '' : ':' . $port);
        if (!hash_equals($canonical, $origin)) {
            throw new OidcConfigurationException('App.fullBaseUrl must be a canonical HTTPS origin.');
        }

        return $origin;
    }

    /** @return list<string> */
    private function amr(string|false $value): array
    {
        if ($value === false || $value === '') {
            return [];
        }
        try {
            $items = json_decode($value, true, 4, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new OidcConfigurationException(self::RELEASE_AMR . ' must be an empty value or a JSON string array.');
        }
        if (!is_array($items) || !array_is_list($items) || count($items) > 16) {
            throw new OidcConfigurationException(self::RELEASE_AMR . ' must be a JSON string array.');
        }
        $result = [];
        foreach ($items as $item) {
            if (!is_string($item) || $item === '' || strlen($item) > 64 || trim($item) !== $item) {
                throw new OidcConfigurationException(self::RELEASE_AMR . ' contains an invalid value.');
            }
            $result[] = $item;
        }
        if (count(array_unique($result)) !== count($result)) {
            throw new OidcConfigurationException(self::RELEASE_AMR . ' contains duplicate values.');
        }

        return $result;
    }

    /**
     * Validate a required, bounded environment value.
     */
    private function required(string|false $value, string $name, int $maxLength): string
    {
        if (
            !is_string($value) || $value === '' || strlen($value) > $maxLength || trim($value) !== $value ||
            preg_match('/[\x00-\x1F\x7F]/', $value)
        ) {
            throw new OidcConfigurationException($name . ' is missing or invalid.');
        }

        return $value;
    }
}
