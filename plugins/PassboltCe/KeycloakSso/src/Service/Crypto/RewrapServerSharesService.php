<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Crypto;

use Cake\Datasource\ConnectionManager;
use Cake\I18n\DateTime;
use Cake\ORM\Locator\LocatorAwareTrait;
use Passbolt\KeycloakSso\Cryptography\Protocol\CborProtocolV1;
use Passbolt\KeycloakSso\Cryptography\ServerShareProtector;
use Passbolt\KeycloakSso\Error\Exception\CryptoSsoException;
use Passbolt\KeycloakSso\Model\Dto\CryptoConfigurationDto;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoCryptoEnrollment;

final class RewrapServerSharesService
{
    use LocatorAwareTrait;

    /**
     * Construct the server-share KEK rotation service.
     */
    public function __construct(
        private readonly CryptoConfigurationDto $configuration,
        private readonly ServerShareProtector $shares,
    ) {
    }

    /** Re-encrypt all active shares under the configured active KEK. */
    public function rewrap(): int
    {
        $table = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoCryptoEnrollments');
        $ids = $table->find()->select(['id'])->where([
            'status' => KeycloakSsoCryptoEnrollment::STATUS_ACTIVE,
            'revoked IS' => null,
            'server_share_key_id !=' => $this->configuration->activeServerShareKeyId,
        ])->all()->extract('id')->toList();
        $rewrapped = 0;
        /** @var \Cake\Database\Connection $connection */
        $connection = ConnectionManager::get('default');
        foreach ($ids as $id) {
            $changed = $connection->transactional(function () use ($table, $id): bool {
                /** @var \Passbolt\KeycloakSso\Model\Entity\KeycloakSsoCryptoEnrollment|null $enrollment */
                $enrollment = $table->find()->where([
                    'id' => $id,
                    'status' => KeycloakSsoCryptoEnrollment::STATUS_ACTIVE,
                    'revoked IS' => null,
                ])->epilog('FOR UPDATE')->first();
                if (
                    $enrollment === null ||
                    hash_equals(
                        $this->configuration->activeServerShareKeyId,
                        (string)$enrollment->get('server_share_key_id')
                    )
                ) {
                    return false;
                }
                $contextBytes = base64_decode((string)$enrollment->get('context_cbor'), true);
                if (
                    $contextBytes === false ||
                    !hash_equals(base64_encode($contextBytes), (string)$enrollment->get('context_cbor'))
                ) {
                    throw new CryptoSsoException('enrollment_context_invalid');
                }
                $aad = CborProtocolV1::encodeBinding(
                    'release_package',
                    CborProtocolV1::decodeContext($contextBytes)
                );
                $share = $this->shares->decrypt(
                    (string)$enrollment->get('server_share_ciphertext'),
                    (string)$enrollment->get('server_share_nonce'),
                    (string)$enrollment->get('server_share_key_id'),
                    $aad
                );
                try {
                    $protected = $this->shares->encrypt($share, $aad);
                } finally {
                    sodium_memzero($share);
                }
                $affected = $table->updateAll([
                    'server_share_ciphertext' => $protected['ciphertext'],
                    'server_share_nonce' => $protected['nonce'],
                    'server_share_key_id' => $protected['keyId'],
                    'modified' => DateTime::now(),
                ], [
                    'id' => $enrollment->id,
                    'status' => KeycloakSsoCryptoEnrollment::STATUS_ACTIVE,
                    'server_share_key_id' => $enrollment->get('server_share_key_id'),
                ]);
                if ($affected !== 1) {
                    throw new CryptoSsoException('server_share_rewrap_race');
                }

                return true;
            });
            if ($changed) {
                $rewrapped++;
            }
        }

        return $rewrapped;
    }
}
