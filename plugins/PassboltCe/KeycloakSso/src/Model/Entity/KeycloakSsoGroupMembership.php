<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Entity;

use Cake\ORM\Entity;

/**
 * @property string $id
 * @property string $provisioned_group_id
 * @property string $user_id
 * @property string $status
 * @property string|null $failure_code
 */
final class KeycloakSsoGroupMembership extends Entity
{
    public const STATUS_PENDING_ACTIVATION = 'pending_activation';
    public const STATUS_PENDING_CRYPTO = 'pending_crypto';
    public const STATUS_ACTIVE = 'active';
    public const STATUS_FAILED = 'failed';

    protected array $_accessible = ['*' => false];
}
