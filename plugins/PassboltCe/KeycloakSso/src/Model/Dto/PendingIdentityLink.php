<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Dto;

final readonly class PendingIdentityLink
{
    /**
     * Hold the validated identity only inside the short-lived linking boundary.
     */
    public function __construct(
        public string $issuer,
        public string $subject,
        public string $email,
    ) {
    }
}
