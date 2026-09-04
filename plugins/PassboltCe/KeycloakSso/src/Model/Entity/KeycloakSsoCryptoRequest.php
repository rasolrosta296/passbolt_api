<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Entity;

use Cake\ORM\Entity;

/**
 * @property string $id
 * @property string $purpose
 * @property string $user_id
 * @property string $identity_id
 * @property string $enrollment_id
 * @property string|null $request_ciphertext
 * @property string|null $client_nonce_hash
 * @property string $status
 * @property \Cake\I18n\DateTime $expires
 * @property \Cake\I18n\DateTime $created
 * @property \Cake\I18n\DateTime $modified
 */
final class KeycloakSsoCryptoRequest extends Entity
{
    public const PURPOSE_ENROLLMENT = 'crypto_enrollment';
    public const PURPOSE_RELEASE = 'crypto_release';
    public const STATUS_PENDING_OIDC = 'pending_oidc';
    public const STATUS_OIDC_VERIFIED = 'oidc_verified';
    public const STATUS_PROCESSING = 'processing';
    public const STATUS_CONSUMED = 'consumed';
    public const STATUS_FAILED = 'failed';

    protected array $_accessible = ['*' => false];
    protected array $_hidden = ['request_ciphertext', 'client_nonce_hash'];
}
