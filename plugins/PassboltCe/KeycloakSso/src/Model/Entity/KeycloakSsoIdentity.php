<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Entity;

use Cake\I18n\DateTime;
use Cake\ORM\Entity;

/**
 * @property string $id
 * @property string $user_id
 * @property string $issuer
 * @property string $subject
 * @property string $email_at_link_time
 * @property \Cake\I18n\DateTime $created
 * @property \Cake\I18n\DateTime $modified
 * @property \Cake\I18n\DateTime $last_seen
 */
final class KeycloakSsoIdentity extends Entity
{
    protected array $_accessible = ['*' => false];

    protected array $_hidden = [
        'subject',
        'email_at_link_time',
    ];

    /**
     * Record that the immutable provider identity was freshly observed.
     */
    public function markSeen(?DateTime $now = null): void
    {
        $this->set('last_seen', $now ?? DateTime::now());
    }
}
