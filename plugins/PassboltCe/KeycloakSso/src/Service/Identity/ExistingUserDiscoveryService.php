<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Identity;

use App\Model\Entity\User;
use Cake\ORM\Locator\LocatorAwareTrait;
use Passbolt\KeycloakSso\Error\Exception\OidcValidationException;

final class ExistingUserDiscoveryService
{
    use LocatorAwareTrait;

    /**
     * Find exactly one active Passbolt user by normalized verified email.
     */
    public function findExactlyOne(string $verifiedEmail): User
    {
        $normalizedEmail = mb_strtolower($verifiedEmail, 'UTF-8');
        /** @var \App\Model\Table\UsersTable $users */
        $users = $this->fetchTable('Users');
        $matches = $users->find('activeNotDeletedNotDisabledContainRole')
            ->where(['LOWER(Users.username)' => $normalizedEmail])
            ->limit(2)
            ->all()
            ->toList();
        if (count($matches) !== 1 || !($matches[0] instanceof User)) {
            throw new OidcValidationException('existing_user_not_unique');
        }

        return $matches[0];
    }
}
