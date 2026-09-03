<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Dto;

final readonly class OidcAuthorizationRequest
{
    public function __construct(
        public string $url,
        public string $browserBinding,
    ) {
    }
}
