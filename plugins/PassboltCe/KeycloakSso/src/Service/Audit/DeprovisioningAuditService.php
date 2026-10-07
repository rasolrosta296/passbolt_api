<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Audit;

use Cake\Log\Log;

final class DeprovisioningAuditService
{
    private const EVENTS = ['checked', 'deprovisioned', 'reactivation_required', 'deleted', 'failed'];
    private const CATEGORIES = ['none', 'disabled', 'deleted', 'access_cleanup', 'ownership', 'unexpected'];

    /** Record only fixed categories and an internal UUID. */
    public function record(string $event, string $category, ?string $userId): void
    {
        $event = in_array($event, self::EVENTS, true) ? $event : 'failed';
        $category = in_array($category, self::CATEGORIES, true) ? $category : 'unexpected';
        $user = is_string($userId) && preg_match('/^[0-9a-f-]{36}$/D', $userId) === 1
            ? $userId
            : 'none';
        Log::info(sprintf(
            'Keycloak deprovisioning event=%s category=%s user=%s.',
            $event,
            $category,
            $user
        ));
    }
}
