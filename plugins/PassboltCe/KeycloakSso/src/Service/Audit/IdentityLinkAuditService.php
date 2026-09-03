<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Audit;

use Cake\Log\Log;

final class IdentityLinkAuditService
{
    private const FAILURE_CATEGORIES = [
        'authentication_required',
        'identity_mismatch',
        'transaction_invalid',
        'collision',
        'persistence_failure',
        'unexpected_failure',
    ];

    /** Record link initiation without OIDC data. */
    public function linkStarted(string $userId): void
    {
        Log::info(sprintf('Keycloak identity link started; user_id=%s.', $userId));
    }

    /** Record successful linking without OIDC data. */
    public function linkSucceeded(string $userId): void
    {
        Log::info(sprintf('Keycloak identity link succeeded; user_id=%s.', $userId));
    }

    /** Record an allowlisted failure category without OIDC data. */
    public function linkFailed(string $userId, string $category): void
    {
        if (!in_array($category, self::FAILURE_CATEGORIES, true)) {
            $category = 'unexpected_failure';
        }
        Log::warning(sprintf('Keycloak identity link failed; user_id=%s; category=%s.', $userId, $category));
    }

    /** Record a uniqueness collision without provider identifiers. */
    public function collision(string $userId): void
    {
        Log::warning(sprintf('Keycloak identity link collision detected; user_id=%s.', $userId));
    }

    /** Record successful unlinking without OIDC data. */
    public function unlinkSucceeded(string $userId): void
    {
        Log::info(sprintf('Keycloak identity unlink succeeded; user_id=%s.', $userId));
    }
}
