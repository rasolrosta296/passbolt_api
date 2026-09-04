<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Entity;

use Cake\ORM\Entity;

/**
 * @property string $id
 * @property string $user_id
 * @property string $capability_hash
 * @property string|null $capability_ciphertext
 * @property string $status
 * @property \Cake\I18n\DateTime $created
 * @property \Cake\I18n\DateTime $modified
 * @property \Cake\I18n\DateTime|null $finished
 */
final class KeycloakSsoRotationBarrier extends Entity
{
    public const STATUS_ACTIVE = 'active';
    public const STATUS_COMPLETED = 'completed';
    public const STATUS_FAILED = 'failed';

    protected array $_accessible = ['*' => false];
    protected array $_hidden = ['capability_hash', 'capability_ciphertext'];
}
