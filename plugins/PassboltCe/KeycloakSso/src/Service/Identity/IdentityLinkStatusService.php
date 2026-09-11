<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Identity;

use Cake\ORM\Locator\LocatorAwareTrait;

final class IdentityLinkStatusService
{
    use LocatorAwareTrait;

    /** Build a status reader restricted to one configured issuer namespace. */
    public function __construct(private readonly string $issuer)
    {
    }

    /** Check only the immutable configured-issuer mapping for the authenticated user. */
    public function isLinked(string $userId): bool
    {
        return $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoIdentities')
            ->find()
            ->where([
                'issuer' => $this->issuer,
                'user_id' => $userId,
            ])
            ->count() === 1;
    }
}
