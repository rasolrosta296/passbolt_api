<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Identity;

use Cake\ORM\Locator\LocatorAwareTrait;
use Passbolt\KeycloakSso\Error\Exception\IdentityLinkException;
use Passbolt\KeycloakSso\Service\Audit\IdentityLinkAuditService;

final class UnlinkIdentityService
{
    use LocatorAwareTrait;

    /** Construct the current-user unlink service. */
    public function __construct(
        private readonly string $issuer,
        private readonly IdentityLinkAuditService $audit,
    ) {
    }

    /**
     * Remove only the caller's mapping for the configured issuer.
     */
    public function unlink(string $userId): void
    {
        $deleted = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoIdentities')->deleteAll([
            'issuer' => $this->issuer,
            'user_id' => $userId,
        ]);
        if ($deleted !== 1) {
            throw new IdentityLinkException('identity_not_linked');
        }
        $this->audit->unlinkSucceeded($userId);
    }
}
