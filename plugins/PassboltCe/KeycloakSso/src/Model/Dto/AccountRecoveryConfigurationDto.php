<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Dto;

final readonly class AccountRecoveryConfigurationDto
{
    /** @param list<string> $requiredAmrValues */
    public function __construct(
        public string $requiredAcr,
        public array $requiredAmrValues,
    ) {
    }
}
