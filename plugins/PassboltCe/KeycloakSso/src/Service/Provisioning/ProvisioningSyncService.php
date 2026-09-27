<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Provisioning;

use Cake\ORM\Locator\LocatorAwareTrait;
use Cake\ORM\Table;
use Passbolt\KeycloakSso\Model\Dto\KeycloakAdminEventDto;
use Passbolt\KeycloakSso\Model\Dto\ProvisioningConfigurationDto;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoProvisioningEvent;

final class ProvisioningSyncService
{
    use LocatorAwareTrait;

    private const MAX_PAGES_PER_RUN = 1_000;

    /** Construct the bounded event synchronization service. */
    public function __construct(
        private readonly ProvisioningConfigurationDto $configuration,
        private readonly KeycloakProvisioningApiService $api,
        private readonly ProvisionKeycloakUserService $provisioner,
    ) {
    }

    /**
     * Synchronize saved Keycloak user administrator events.
     *
     * @return array<string, int>
     */
    public function run(bool $dryRun = false, ?int $nowMilliseconds = null): array
    {
        $counts = array_fill_keys([
            ProvisionKeycloakUserService::OUTCOME_PROVISIONED,
            ProvisionKeycloakUserService::OUTCOME_WOULD_PROVISION,
            ProvisionKeycloakUserService::OUTCOME_SKIPPED,
            ProvisionKeycloakUserService::OUTCOME_COLLISION,
            ProvisionKeycloakUserService::OUTCOME_DUPLICATE,
            ProvisionKeycloakUserService::OUTCOME_IN_PROGRESS,
            ProvisionKeycloakUserService::OUTCOME_FAILED,
        ], 0);
        if (!$dryRun) {
            $this->provisioner->recoverStaleClaims();
            $failed = $this->eventsTable()->find()->where([
                'issuer' => $this->configuration->issuer,
                'status' => KeycloakSsoProvisioningEvent::STATUS_FAILED,
            ])->orderByAsc('event_time')->limit($this->configuration->batchSize)->all();
            foreach ($failed as $entity) {
                $outcome = $this->provisioner->process(new KeycloakAdminEventDto(
                    (string)$entity->get('event_id'),
                    (int)$entity->get('event_time'),
                    (string)$entity->get('operation'),
                    (string)$entity->get('subject')
                ));
                $counts[$outcome]++;
            }
        }

        $from = $this->fromMilliseconds($dryRun, $nowMilliseconds ?? (int)floor(microtime(true) * 1_000.0));
        $first = 0;
        for ($page = 0; $page < self::MAX_PAGES_PER_RUN; $page++) {
            $eventPage = $this->api->events($from, $first);
            foreach ($eventPage->events as $event) {
                $outcome = $this->provisioner->process($event, $dryRun);
                $counts[$outcome]++;
            }
            $received = $eventPage->received;
            if ($received < $this->configuration->batchSize) {
                break;
            }
            $first += $received;
        }

        return $counts;
    }

    /** Compute the inclusive Keycloak cursor with a replay-safe overlap. */
    private function fromMilliseconds(bool $dryRun, int $nowMilliseconds): int
    {
        if ($nowMilliseconds < 0) {
            return 0;
        }
        if (!$dryRun) {
            $query = $this->eventsTable()->find();
            $latest = $query->select([
                'latest' => $query->func()->max('event_time'),
            ])->where(['issuer' => $this->configuration->issuer])->first();
            $eventTime = $latest?->get('latest');
            if (is_int($eventTime) || (is_string($eventTime) && ctype_digit($eventTime))) {
                return max(0, (int)$eventTime - ($this->configuration->overlapSeconds * 1_000));
            }
            if (
                is_float($eventTime) && is_finite($eventTime) && $eventTime >= 0 &&
                $eventTime <= PHP_INT_MAX && floor($eventTime) === $eventTime
            ) {
                return max(0, (int)$eventTime - ($this->configuration->overlapSeconds * 1_000));
            }
        }

        return max(0, $nowMilliseconds - ($this->configuration->initialLookbackSeconds * 1_000));
    }

    /** @return \Passbolt\KeycloakSso\Model\Table\KeycloakSsoProvisioningEventsTable */
    private function eventsTable(): Table
    {
        return $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoProvisioningEvents');
    }
}
