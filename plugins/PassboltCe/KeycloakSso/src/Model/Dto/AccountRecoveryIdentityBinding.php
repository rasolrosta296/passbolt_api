<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Dto;

final readonly class AccountRecoveryIdentityBinding
{
    /** Carry the exact immutable identity authorized by the OIDC callback. */
    public function __construct(
        public string $identityId,
        public string $userId,
        public string $issuer,
        public string $subject,
    ) {
    }
}
