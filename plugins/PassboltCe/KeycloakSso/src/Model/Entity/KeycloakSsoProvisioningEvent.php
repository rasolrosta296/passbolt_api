<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Entity;

use Cake\ORM\Entity;

/**
 * @property string $id
 * @property string $event_id
 * @property string $issuer
 * @property string $subject
 * @property int $event_time
 * @property string $operation
 * @property string $status
 * @property string|null $user_id
 * @property string|null $failure_code
 */
final class KeycloakSsoProvisioningEvent extends Entity
{
    public const STATUS_PENDING = 'pending';
    public const STATUS_PROCESSING = 'processing';
    public const STATUS_PROVISIONED = 'provisioned';
    public const STATUS_SKIPPED = 'skipped';
    public const STATUS_COLLISION = 'collision';
    public const STATUS_FAILED = 'failed';

    protected array $_accessible = ['*' => false];

    protected array $_hidden = [
        'subject',
        'failure_code',
    ];
}
