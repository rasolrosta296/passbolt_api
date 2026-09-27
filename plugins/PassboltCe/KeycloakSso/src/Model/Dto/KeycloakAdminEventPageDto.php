<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Dto;

final readonly class KeycloakAdminEventPageDto
{
    /**
     * Construct one filtered event page while retaining its raw page size.
     *
     * @param list<\Passbolt\KeycloakSso\Model\Dto\KeycloakAdminEventDto> $events
     */
    public function __construct(
        public array $events,
        public int $received,
    ) {
    }
}
