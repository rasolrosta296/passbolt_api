<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Oidc;

use Passbolt\KeycloakSso\Error\Exception\OidcNetworkException;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;
use Passbolt\KeycloakSso\Model\Dto\OidcDiscoveryDocument;
use Passbolt\KeycloakSso\Utility\Http\OidcHttpClientInterface;
use Passbolt\KeycloakSso\Utility\Http\SafeOidcHttpClient;

final class OidcDiscoveryService
{
    /**
     * @param \Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto $configuration Configuration.
     * @param \Passbolt\KeycloakSso\Utility\Http\OidcHttpClientInterface $httpClient Guarded client.
     * @param \Passbolt\KeycloakSso\Service\Oidc\OidcMetadataCache $cache Metadata cache.
     */
    public function __construct(
        private readonly OidcConfigurationDto $configuration,
        private readonly OidcHttpClientInterface $httpClient,
        private readonly OidcMetadataCache $cache,
    ) {
    }

    /**
     * Fetch and validate discovery metadata.
     */
    public function get(bool $forceRefresh = false): OidcDiscoveryDocument
    {
        $hash = $this->configuration->configurationHash();
        $document = $forceRefresh ? null : $this->cache->read('discovery', $hash);
        if ($document === null) {
            $document = $this->httpClient->requestJson('GET', $this->configuration->discoveryUrl());
            $this->validate($document);
            $this->cache->write('discovery', $hash, $document);
        } else {
            $this->validate($document);
        }

        return new OidcDiscoveryDocument(
            $document['issuer'],
            $document['authorization_endpoint'],
            $document['token_endpoint'],
            $document['jwks_uri']
        );
    }

    /** @param array<string, mixed> $document */
    private function validate(array $document): void
    {
        foreach (['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri'] as $field) {
            if (!isset($document[$field]) || !is_string($document[$field]) || $document[$field] === '') {
                throw new OidcNetworkException('The OIDC discovery document is incomplete.');
            }
        }
        if (!hash_equals($this->configuration->issuer, $document['issuer'])) {
            throw new OidcNetworkException('The OIDC discovery issuer does not match configuration.');
        }
        foreach (['authorization_endpoint', 'token_endpoint', 'jwks_uri'] as $field) {
            if (!($this->httpClient instanceof SafeOidcHttpClient)) {
                $this->assertHttpsSameOrigin($document[$field]);
            } else {
                $this->httpClient->assertSafeUrl($document[$field]);
            }
        }
        if (!in_array('code', $document['response_types_supported'] ?? [], true)) {
            throw new OidcNetworkException('The OIDC provider does not advertise Authorization Code Flow.');
        }
        if (!in_array('RS256', $document['id_token_signing_alg_values_supported'] ?? [], true)) {
            throw new OidcNetworkException('The OIDC provider does not advertise the required signing algorithm.');
        }
        if (!in_array('S256', $document['code_challenge_methods_supported'] ?? [], true)) {
            throw new OidcNetworkException('The OIDC provider does not advertise PKCE S256.');
        }
        $scopes = $document['scopes_supported'] ?? [];
        if (!in_array('openid', $scopes, true) || !in_array('email', $scopes, true)) {
            throw new OidcNetworkException('The OIDC provider does not advertise the required scopes.');
        }
    }

    private function assertHttpsSameOrigin(string $url): void
    {
        $issuer = parse_url($this->configuration->issuer);
        $endpoint = parse_url($url);
        if (
            $issuer === false || $endpoint === false || ($endpoint['scheme'] ?? null) !== 'https' ||
            strtolower((string)($issuer['host'] ?? '')) !== strtolower((string)($endpoint['host'] ?? '')) ||
            ($issuer['port'] ?? 443) !== ($endpoint['port'] ?? 443)
        ) {
            throw new OidcNetworkException('The OIDC endpoint origin is not allowed.');
        }
    }
}
