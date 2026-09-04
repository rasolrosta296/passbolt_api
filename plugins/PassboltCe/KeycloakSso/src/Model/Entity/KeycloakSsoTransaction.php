<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Entity;

use Cake\I18n\DateTime;
use Cake\ORM\Entity;

/**
 * @property string $id
 * @property string $state_hash
 * @property string $nonce_hash
 * @property string $browser_binding_hash
 * @property string|null $pkce_verifier_ciphertext
 * @property string $configuration_hash
 * @property string $issuer
 * @property string $client_id
 * @property string $redirect_uri
 * @property string $purpose
 * @property string|null $requested_user_id
 * @property string|null $link_identity_ciphertext
 * @property string|null $crypto_request_id
 * @property string $status
 * @property string|null $result_token_hash
 * @property string|null $failure_code
 * @property \Cake\I18n\DateTime $expires
 * @property \Cake\I18n\DateTime|null $result_expires
 * @property \Cake\I18n\DateTime $created
 * @property \Cake\I18n\DateTime $modified
 */
final class KeycloakSsoTransaction extends Entity
{
    public const STATUS_PENDING = 'pending';
    public const STATUS_PROCESSING = 'processing';
    public const STATUS_SUCCEEDED = 'succeeded';
    public const STATUS_FAILED = 'failed';
    public const STATUS_RESULT_CONSUMED = 'result_consumed';
    public const STATUS_LINKING = 'linking';
    public const STATUS_CRYPTO_PROCESSING = 'crypto_processing';

    public const PURPOSE_IDENTITY_PROOF = 'identity_proof';
    public const PURPOSE_IDENTITY_LINK = 'identity_link';
    public const PURPOSE_CRYPTO_ENROLLMENT = 'crypto_enrollment';
    public const PURPOSE_CRYPTO_RELEASE = 'crypto_release';

    protected array $_accessible = ['*' => false];

    protected array $_hidden = [
        'state_hash',
        'nonce_hash',
        'browser_binding_hash',
        'pkce_verifier_ciphertext',
        'configuration_hash',
        'result_token_hash',
        'link_identity_ciphertext',
        'crypto_request_id',
    ];

    /**
     * Return whether the transaction has expired.
     */
    public function isExpired(?DateTime $now = null): bool
    {
        return $this->expires <= ($now ?? DateTime::now());
    }
}
