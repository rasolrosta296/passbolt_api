<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Event;

use Cake\Datasource\EntityInterface;
use Cake\Event\EventInterface;
use Cake\Event\EventListenerInterface;
use Cake\ORM\Table;
use Passbolt\KeycloakSso\Service\Audit\CryptoSsoAuditService;
use Passbolt\KeycloakSso\Service\Crypto\RevokeCryptoEnrollmentsService;

final class RevokeCryptoEnrollmentsOnGpgkeyChange implements EventListenerInterface
{
    /** @inheritDoc */
    public function implementedEvents(): array
    {
        return ['Model.afterSave' => 'revoke'];
    }

    /**
     * Revoke old-fingerprint enrollments inside the GPG-key save transaction.
     */
    public function revoke(EventInterface $event): void
    {
        $table = $event->getSubject();
        $entity = $event->getData('entity');
        if (
            !($table instanceof Table) ||
            $table->getAlias() !== 'Gpgkeys' ||
            !($entity instanceof EntityInterface) ||
            (!$entity->isNew() &&
                !$entity->isDirty('fingerprint') &&
                !$entity->isDirty('armored_key') &&
                !$entity->isDirty('deleted'))
        ) {
            return;
        }
        $userId = $entity->get('user_id');
        if (!is_string($userId) || $userId === '') {
            return;
        }

        $revoked = (new RevokeCryptoEnrollmentsService())->revokeAllForUser($userId);
        if ($revoked !== []) {
            (new CryptoSsoAuditService())->record('enrollment_revoked', $userId, 'cryptography');
        }
    }
}
