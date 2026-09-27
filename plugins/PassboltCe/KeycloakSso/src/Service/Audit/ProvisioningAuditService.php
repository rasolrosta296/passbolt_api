<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Audit;

use Cake\Log\Log;

final class ProvisioningAuditService
{
    private const EVENTS = ['provisioned', 'skipped', 'collision', 'failed'];
    private const CATEGORIES = [
        'none',
        'disabled',
        'unverified_email',
        'invalid_profile',
        'existing_user',
        'identity_collision',
        'actor_unavailable',
        'keycloak_unavailable',
        'persistence',
        'unexpected',
    ];

    /** Record a data-minimized provisioning outcome. */
    public function record(string $event, string $category = 'none', ?string $userId = null): void
    {
        if (!in_array($event, self::EVENTS, true)) {
            $event = 'failed';
        }
        if (!in_array($category, self::CATEGORIES, true)) {
            $category = 'unexpected';
        }
        $user = is_string($userId) && preg_match('/^[0-9a-f-]{36}$/D', $userId) === 1
            ? $userId
            : 'none';
        Log::info(sprintf(
            'Keycloak user provisioning event=%s category=%s user=%s.',
            $event,
            $category,
            $user
        ));
    }
}
