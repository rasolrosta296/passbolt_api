<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Dto;

final readonly class OidcDiscoveryDocument
{
    /**
     * @param string $issuer Exact OIDC issuer.
     * @param string $authorizationEndpoint Authorization endpoint.
     * @param string $tokenEndpoint Token endpoint.
     * @param string $jwksUri JWKS endpoint.
     */
    public function __construct(
        public string $issuer,
        public string $authorizationEndpoint,
        public string $tokenEndpoint,
        public string $jwksUri,
    ) {
    }
}
