<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Identity;

use App\Utility\UuidFactory;
use Cake\I18n\DateTime;
use Cake\ORM\Locator\LocatorAwareTrait;
use Passbolt\KeycloakSso\Error\Exception\IdentityLinkException;
use Passbolt\KeycloakSso\Model\Dto\PendingIdentityLink;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoIdentity;
use Throwable;

final class IdentityLinkPersistenceService
{
    use LocatorAwareTrait;

    /**
     * Persist a new immutable identity mapping, relying on database uniqueness for races.
     */
    public function create(string $userId, PendingIdentityLink $identity): KeycloakSsoIdentity
    {
        $this->assertAvailable($userId, $identity->issuer, $identity->subject);
        $table = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoIdentities');
        $entity = $table->newEmptyEntity();
        $now = DateTime::now();
        $entity->set('id', UuidFactory::uuid());
        $entity->set('user_id', $userId);
        $entity->set('issuer', $identity->issuer);
        $entity->set('subject', $identity->subject);
        $entity->set('email_at_link_time', $identity->email);
        $entity->set('last_seen', $now);

        try {
            $saved = $table->saveOrFail($entity);
        } catch (Throwable $exception) {
            if ($this->hasCollision($userId, $identity->issuer, $identity->subject)) {
                throw new IdentityLinkException('database_identity_collision');
            }
            throw new IdentityLinkException('identity_persistence_failed');
        }
        if (!($saved instanceof KeycloakSsoIdentity)) {
            throw new IdentityLinkException('identity_persistence_failed');
        }

        return $saved;
    }

    /**
     * Fail when either provider identity or provider/user slot is already occupied.
     */
    public function assertAvailable(string $userId, string $issuer, string $subject): void
    {
        $table = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoIdentities');
        $byIdentity = $table->find()->where(['issuer' => $issuer, 'subject' => $subject])->first();
        if ($byIdentity !== null) {
            $reason = hash_equals((string)$byIdentity->get('user_id'), $userId)
                ? 'identity_already_linked'
                : 'provider_identity_collision';
            throw new IdentityLinkException($reason);
        }
        if ($table->find()->where(['issuer' => $issuer, 'user_id' => $userId])->first() !== null) {
            throw new IdentityLinkException('provider_user_collision');
        }
    }

    /** Detect whether persistence lost a uniqueness race. */
    private function hasCollision(string $userId, string $issuer, string $subject): bool
    {
        $table = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoIdentities');

        return $table->find()->where(['issuer' => $issuer, 'subject' => $subject])->count() > 0 ||
            $table->find()->where(['issuer' => $issuer, 'user_id' => $userId])->count() > 0;
    }
}
