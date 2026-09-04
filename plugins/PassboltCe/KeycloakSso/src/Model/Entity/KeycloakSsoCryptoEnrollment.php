<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Entity;

use Cake\ORM\Entity;

/**
 * @property string $id
 * @property string $user_id
 * @property string $identity_id
 * @property string $client_enrollment_uuid
 * @property string $context_cbor
 * @property string $signing_public_key
 * @property string $signing_key_thumbprint
 * @property string $server_share_ciphertext
 * @property string $server_share_nonce
 * @property string $server_share_key_id
 * @property string $client_blob_digest
 * @property string $passbolt_key_fingerprint
 * @property string $protocol_version
 * @property string $crypto_suite
 * @property string $status
 * @property \Cake\I18n\DateTime $created
 * @property \Cake\I18n\DateTime $modified
 * @property \Cake\I18n\DateTime|null $last_used
 * @property \Cake\I18n\DateTime|null $revoked
 */
final class KeycloakSsoCryptoEnrollment extends Entity
{
    public const STATUS_ACTIVE = 'active';
    public const STATUS_REVOKED = 'revoked';

    protected array $_accessible = ['*' => false];

    protected array $_hidden = [
        'server_share_ciphertext',
        'server_share_nonce',
        'server_share_key_id',
        'signing_public_key',
        'context_cbor',
    ];
}
