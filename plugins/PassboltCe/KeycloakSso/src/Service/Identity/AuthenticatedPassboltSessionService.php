<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Identity;

use App\Model\Entity\User;
use Cake\Http\ServerRequest;
use Cake\ORM\Locator\LocatorAwareTrait;
use Cake\Validation\Validation;
use Passbolt\KeycloakSso\Error\Exception\IdentityLinkException;

final class AuthenticatedPassboltSessionService
{
    use LocatorAwareTrait;

    /**
     * Require a server-side Passbolt session matching the request identity.
     */
    public function getActiveUser(ServerRequest $request, ?string $requestIdentityId): User
    {
        $sessionUserId = $request->getSession()->read('Auth.user.id');
        if (
            !is_string($sessionUserId) || !Validation::uuid($sessionUserId) ||
            !is_string($requestIdentityId) || !Validation::uuid($requestIdentityId) ||
            !hash_equals($sessionUserId, $requestIdentityId)
        ) {
            throw new IdentityLinkException('passbolt_session_required');
        }

        /** @var \App\Model\Entity\User|null $user */
        $user = $this->fetchTable('Users')
            ->find('activeNotDeletedNotDisabledContainRole')
            ->where(['Users.id' => $sessionUserId])
            ->first();
        if (!($user instanceof User)) {
            throw new IdentityLinkException('passbolt_user_unavailable');
        }

        return $user;
    }
}
