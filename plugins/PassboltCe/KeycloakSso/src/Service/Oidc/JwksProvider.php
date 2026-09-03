<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Oidc;

use Passbolt\KeycloakSso\Error\Exception\OidcNetworkException;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;
use Passbolt\KeycloakSso\Utility\Http\OidcHttpClientInterface;

final class JwksProvider implements JwksProviderInterface
{
    /**
     * @param \Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto $configuration Configuration.
     * @param \Passbolt\KeycloakSso\Service\Oidc\OidcDiscoveryService $discovery Discovery service.
     * @param \Passbolt\KeycloakSso\Utility\Http\OidcHttpClientInterface $httpClient Guarded client.
     * @param \Passbolt\KeycloakSso\Service\Oidc\OidcMetadataCache $cache Metadata cache.
     */
    public function __construct(
        private readonly OidcConfigurationDto $configuration,
        private readonly OidcDiscoveryService $discovery,
        private readonly OidcHttpClientInterface $httpClient,
        private readonly OidcMetadataCache $cache,
    ) {
    }

    /** @return array{keys: list<array<string, mixed>>} */
    public function get(bool $forceRefresh = false): array
    {
        $hash = $this->configuration->configurationHash();
        $jwks = $forceRefresh ? null : $this->cache->read('jwks', $hash);
        if ($jwks === null) {
            $jwks = $this->httpClient->requestJson('GET', $this->discovery->get($forceRefresh)->jwksUri);
            $this->validate($jwks);
            $this->cache->write('jwks', $hash, $jwks);
        } else {
            $this->validate($jwks);
        }

        /** @var array{keys: list<array<string, mixed>>} $jwks */
        return $jwks;
    }

    /** @param array<string, mixed> $jwks */
    private function validate(array $jwks): void
    {
        if (!isset($jwks['keys']) || !is_array($jwks['keys']) || $jwks['keys'] === [] || count($jwks['keys']) > 20) {
            throw new OidcNetworkException('The OIDC JWKS is invalid.');
        }

        $kids = [];
        foreach ($jwks['keys'] as $key) {
            if (
                !is_array($key) || ($key['kty'] ?? null) !== 'RSA' ||
                !isset($key['kid'], $key['n'], $key['e']) ||
                !is_string($key['kid']) || $key['kid'] === '' || strlen($key['kid']) > 255 ||
                !is_string($key['n']) || !preg_match('/^[A-Za-z0-9_-]{342,2048}$/', $key['n']) ||
                !is_string($key['e']) || !preg_match('/^[A-Za-z0-9_-]{2,16}$/', $key['e']) ||
                (($key['use'] ?? 'sig') !== 'sig') || (($key['alg'] ?? 'RS256') !== 'RS256') ||
                (isset($key['key_ops']) && (
                    !is_array($key['key_ops']) || !in_array('verify', $key['key_ops'], true)
                )) ||
                isset($kids[$key['kid']])
            ) {
                throw new OidcNetworkException('The OIDC JWKS contains an invalid or duplicate key.');
            }
            $kids[$key['kid']] = true;
        }
    }
}
