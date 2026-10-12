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
 * @property string $lifecycle_status
 * @property \Cake\I18n\DateTime|null $last_seen
 * @property \Cake\I18n\DateTime|null $last_checked
 * @property \Cake\I18n\DateTime|null $absent_since
 * @property \Cake\I18n\DateTime|null $deprovisioned_at
 * @property \Cake\I18n\DateTime|null $deletion_eligible_at
 * @property \Cake\I18n\DateTime|null $managed_disabled_at
 * @property string|null $deprovision_reason
 */
final class KeycloakSsoProvisionedUser extends Entity
{
    public const STATUS_ACTIVE = 'active';
    public const STATUS_DEPROVISIONING = 'deprovisioning';
    public const STATUS_REACTIVATION_REQUIRED = 'reactivation_required';
    public const STATUS_DEPROVISIONED = 'deprovisioned';
    public const STATUS_QUARANTINED = 'quarantined';
    public const STATUS_DELETED = 'deleted';

    public const REASON_DISABLED = 'keycloak_disabled';
    public const REASON_DELETED = 'keycloak_deleted';

    protected array $_accessible = ['*' => false];

    protected array $_hidden = [
        'subject',
        'email_at_provisioning',
    ];
}
