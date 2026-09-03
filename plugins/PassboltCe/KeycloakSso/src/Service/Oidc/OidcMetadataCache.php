<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Oidc;

use Cake\Cache\Cache;

final class OidcMetadataCache
{
    private const TTL_SECONDS = 300;

    /** @return array<string, mixed>|null */
    public function read(string $type, string $configurationHash): ?array
    {
        $value = Cache::read($this->key($type, $configurationHash), 'default');
        if (!is_array($value) || !isset($value['expires'], $value['document'])) {
            return null;
        }
        if (!is_int($value['expires']) || $value['expires'] <= time() || !is_array($value['document'])) {
            Cache::delete($this->key($type, $configurationHash), 'default');

            return null;
        }

        return $value['document'];
    }

    /** @param array<string, mixed> $document */
    public function write(string $type, string $configurationHash, array $document): void
    {
        Cache::write($this->key($type, $configurationHash), [
            'expires' => time() + self::TTL_SECONDS,
            'document' => $document,
        ], 'default');
    }

    /**
     * Delete cached metadata.
     */
    public function delete(string $type, string $configurationHash): void
    {
        Cache::delete($this->key($type, $configurationHash), 'default');
    }

    /**
     * Build a configuration-bound cache key.
     */
    private function key(string $type, string $configurationHash): string
    {
        return 'keycloak_sso_' . $type . '_' . $configurationHash;
    }
}
