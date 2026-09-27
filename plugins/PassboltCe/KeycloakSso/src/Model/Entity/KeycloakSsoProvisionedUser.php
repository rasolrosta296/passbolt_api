<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Entity;

use Cake\ORM\Entity;

/**
 * @property string $id
 * @property string $user_id
 * @property string $issuer
 * @property string $subject
 * @property string $email_at_provisioning
 * @property string $source_event_id
 */
final class KeycloakSsoProvisionedUser extends Entity
{
    protected array $_accessible = ['*' => false];

    protected array $_hidden = [
        'subject',
        'email_at_provisioning',
    ];
}
