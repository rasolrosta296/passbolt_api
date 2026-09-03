<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Audit;

use Cake\Log\Log;

final class OidcAuditService
{
    private const ALLOWED_FAILURE_CATEGORIES = [
        'configuration',
        'provider_unavailable',
        'protocol_validation',
        'transaction_validation',
        'user_discovery',
        'unexpected_failure',
    ];

    /**
     * Record successful identity proof without identity or token data.
     */
    public function success(): void
    {
        Log::info('Keycloak OIDC identity proof succeeded; Passbolt cryptographic authentication remains required.');
    }

    /**
     * Record an allowlisted failure category without request data.
     */
    public function failure(string $category): void
    {
        if (!in_array($category, self::ALLOWED_FAILURE_CATEGORIES, true)) {
            $category = 'unexpected_failure';
        }
        Log::warning(sprintf('Keycloak OIDC identity proof failed; category=%s.', $category));
    }
}
