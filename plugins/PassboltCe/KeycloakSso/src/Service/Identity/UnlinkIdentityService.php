<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Identity;

use Cake\Datasource\ConnectionManager;
use Cake\I18n\DateTime;
use Cake\ORM\Locator\LocatorAwareTrait;
use Passbolt\KeycloakSso\Error\Exception\IdentityLinkException;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoCryptoEnrollment;
use Passbolt\KeycloakSso\Service\Audit\CryptoSsoAuditService;
use Passbolt\KeycloakSso\Service\Audit\IdentityLinkAuditService;

final class UnlinkIdentityService
{
    use LocatorAwareTrait;

    /** Construct the current-user unlink service. */
    public function __construct(
        private readonly string $issuer,
        private readonly IdentityLinkAuditService $audit,
    ) {
    }

    /**
     * Remove only the caller's mapping for the configured issuer.
     */
    /** @return list<string> Client-enrollment UUIDs that the extension must remove locally. */
    public function unlink(string $userId): array
    {
        $identities = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoIdentities');
        $enrollments = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoCryptoEnrollments');
        /** @var \Cake\Database\Connection $connection */
        $connection = ConnectionManager::get('default');
        $clientIds = $connection->transactional(function () use ($identities, $enrollments, $userId): array {
            /** @var \Passbolt\KeycloakSso\Model\Entity\KeycloakSsoIdentity|null $identity */
            $identity = $identities->find()->where(['issuer' => $this->issuer, 'user_id' => $userId])
                ->epilog('FOR UPDATE')->first();
            if ($identity === null) {
                throw new IdentityLinkException('identity_not_linked');
            }
            $rows = $enrollments->find()->select(['id', 'client_enrollment_uuid'])->where([
                'identity_id' => $identity->id,
            ])->epilog('FOR UPDATE')->all();
            $ids = [];
            $now = DateTime::now();
            foreach ($rows as $row) {
                /** @var \Passbolt\KeycloakSso\Model\Entity\KeycloakSsoCryptoEnrollment $row */
                $ids[] = (string)$row->get('client_enrollment_uuid');
                $enrollments->updateAll([
                    'status' => KeycloakSsoCryptoEnrollment::STATUS_REVOKED,
                    'revoked' => $now,
                    'server_share_ciphertext' => base64_encode(random_bytes(48)),
                    'server_share_nonce' => base64_encode(random_bytes(24)),
                    'modified' => $now,
                ], ['id' => $row->get('id')]);
            }
            $enrollments->deleteAll(['identity_id' => $identity->id]);
            if ($identities->deleteAll(['id' => $identity->id, 'user_id' => $userId]) !== 1) {
                throw new IdentityLinkException('identity_unlink_failed');
            }

            return $ids;
        });
        $this->audit->unlinkSucceeded($userId);

        if ($clientIds !== []) {
            (new CryptoSsoAuditService())->record('enrollment_revoked', $userId, 'revoked');
        }

        return $clientIds;
    }
}
