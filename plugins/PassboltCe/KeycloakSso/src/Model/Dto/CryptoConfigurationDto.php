<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Dto;

use SensitiveParameter;

final readonly class CryptoConfigurationDto
{
    /**
     * @param array<string, string> $serverShareKeys Raw 32-byte KEKs indexed by stable key ID.
     * @param list<string> $requiredAmrValues
     */
    public function __construct(
        public string $passboltOrigin,
        public string $requiredAcr,
        public array $requiredAmrValues,
        public string $activeServerShareKeyId,
        #[SensitiveParameter]
        public array $serverShareKeys,
    ) {
    }
}
