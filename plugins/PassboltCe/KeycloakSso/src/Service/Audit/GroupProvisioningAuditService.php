<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Audit;

use Cake\Log\Log;

final class GroupProvisioningAuditService
{
    private const EVENTS = [
        'group_created',
        'membership_added',
        'membership_completed',
        'membership_pending',
        'failed',
    ];
    private const CATEGORIES = ['none', 'activation', 'client_crypto', 'collision', 'unavailable', 'unexpected'];

    /** Record a data-minimized group-provisioning outcome. */
    public function record(
        string $event,
        string $category = 'none',
        ?string $userId = null,
        ?string $groupId = null
    ): void {
        if (!in_array($event, self::EVENTS, true)) {
            $event = 'failed';
        }
        if (!in_array($category, self::CATEGORIES, true)) {
            $category = 'unexpected';
        }
        $user = $this->uuidOrNone($userId);
        $group = $this->uuidOrNone($groupId);
        Log::info(sprintf(
            'Keycloak group provisioning event=%s category=%s user=%s group=%s.',
            $event,
            $category,
            $user,
            $group
        ));
    }

    /** Return an internal UUID or the fixed redacted placeholder. */
    private function uuidOrNone(?string $value): string
    {
        return is_string($value) && preg_match('/^[0-9a-f-]{36}$/D', $value) === 1 ? $value : 'none';
    }
}
