<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Dto;

final readonly class DeprovisioningConfigurationDto
{
    public const DEFAULT_GRACE_SECONDS = 604_800;
    public const MIN_GRACE_SECONDS = 3_600;
    public const MAX_GRACE_SECONDS = 2_592_000;

    /** Construct independently gated lifecycle configuration. */
    public function __construct(
        public string $issuer,
        public string $actorUserId,
        public int $batchSize,
        public int $graceSeconds,
        public bool $reactivationEnabled = false,
    ) {
    }
}
