<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Dto;

final readonly class KeycloakAdminEventDto
{
    /** Construct a strictly parsed Keycloak user administrator event. */
    public function __construct(
        public string $eventId,
        public int $eventTime,
        public string $operation,
        public string $subject,
    ) {
    }
}
