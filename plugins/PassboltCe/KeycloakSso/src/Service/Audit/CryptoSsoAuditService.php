<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Audit;

use Cake\Log\Log;

final class CryptoSsoAuditService
{
    /**
     * Record an allowlisted, token-free security event.
     */
    public function record(string $event, ?string $userId = null, string $category = 'none'): void
    {
        $allowedEvents = [
            'enrollment_started', 'enrollment_succeeded', 'enrollment_failed',
            'release_started', 'release_succeeded', 'release_failed',
            'enrollment_revoked', 'enrollment_revocation_failed',
            'rotation_barrier_started', 'rotation_barrier_completed', 'rotation_barrier_failed',
        ];
        $allowedCategories = [
            'none', 'authentication', 'identity', 'protocol', 'freshness', 'cryptography',
            'collision', 'revoked', 'unavailable', 'unexpected',
        ];
        if (!in_array($event, $allowedEvents, true)) {
            $event = 'release_failed';
        }
        if (!in_array($category, $allowedCategories, true)) {
            $category = 'unexpected';
        }
        $user = is_string($userId) && preg_match('/^[0-9a-f-]{36}$/D', $userId) === 1 ? $userId : 'anonymous';
        Log::info(sprintf('Keycloak cryptographic SSO event=%s user=%s category=%s.', $event, $user, $category));
    }
}
