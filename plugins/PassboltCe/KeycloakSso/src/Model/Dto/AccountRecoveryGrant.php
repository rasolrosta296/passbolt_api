<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Dto;

use SensitiveParameter;

final readonly class AccountRecoveryGrant
{
    /**
     * Carry the minimum data needed to enter Passbolt's normal recovery flow.
     */
    public function __construct(
        public string $userId,
        #[SensitiveParameter]
        public string $token,
    ) {
    }
}
