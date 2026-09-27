<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Dto;

use SensitiveParameter;

final readonly class ProvisioningConfigurationDto
{
    public const DEFAULT_INITIAL_LOOKBACK_SECONDS = 86_400;
    public const DEFAULT_OVERLAP_SECONDS = 300;
    public const DEFAULT_BATCH_SIZE = 100;
    public const MIN_INITIAL_LOOKBACK_SECONDS = 60;
    public const MAX_INITIAL_LOOKBACK_SECONDS = 604_800;
    public const MIN_OVERLAP_SECONDS = 60;
    public const MAX_OVERLAP_SECONDS = 3_600;
    public const MIN_BATCH_SIZE = 1;
    public const MAX_BATCH_SIZE = 500;

    /** Construct a fully validated provisioning configuration. */
    public function __construct(
        public string $issuer,
        public string $adminApiBaseUrl,
        public string $clientId,
        #[SensitiveParameter]
        public string $clientSecret,
        public string $actorUserId,
        public int $initialLookbackSeconds,
        public int $overlapSeconds,
        public int $batchSize,
    ) {
    }
}
