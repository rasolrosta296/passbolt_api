<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Crypto;

use Cake\Datasource\ConnectionManager;
use Cake\I18n\DateTime;
use Cake\ORM\Locator\LocatorAwareTrait;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoCryptoEnrollment;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoCryptoRequest;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction;

final class RevokeCryptoEnrollmentsService
{
    use LocatorAwareTrait;

    /**
     * Make every server share for the user permanently non-releasable.
     *
     * Revoked rows are retained so a retry after a lost response can still return
     * the client-enrollment UUIDs required for browser-profile cleanup.
     *
     * @return list<string>
     */
    public function revokeAllForUser(string $userId): array
    {
        /** @var \Cake\Database\Connection $connection */
        $connection = ConnectionManager::get('default');

        return $connection->transactional(function () use ($userId): array {
            $identities = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoIdentities');
            $enrollments = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoCryptoEnrollments');
            $requests = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoCryptoRequests');
            $transactions = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoTransactions');

            $identityRows = $identities->find()->select(['id'])->where(['user_id' => $userId])
                ->orderByAsc('id')->epilog('FOR UPDATE')->all();
            $identityIds = [];
            foreach ($identityRows as $identity) {
                $identityIds[] = (string)$identity->get('id');
            }
            if ($identityIds === []) {
                return [];
            }

            $rows = $enrollments->find()
                ->select(['id', 'client_enrollment_uuid', 'status'])
                ->where(['identity_id IN' => $identityIds, 'user_id' => $userId])
                ->orderByAsc('id')
                ->epilog('FOR UPDATE')
                ->all();
            $enrollmentIds = [];
            $clientEnrollmentIds = [];
            $activeEnrollmentIds = [];
            foreach ($rows as $row) {
                $enrollmentId = (string)$row->get('id');
                $enrollmentIds[] = $enrollmentId;
                $clientEnrollmentIds[] = (string)$row->get('client_enrollment_uuid');
                if (hash_equals(KeycloakSsoCryptoEnrollment::STATUS_ACTIVE, (string)$row->get('status'))) {
                    $activeEnrollmentIds[] = $enrollmentId;
                }
            }
            $requestRows = $requests->find()->select(['id'])->where([
                'identity_id IN' => $identityIds,
                'user_id' => $userId,
                'purpose IN' => [
                    KeycloakSsoCryptoRequest::PURPOSE_ENROLLMENT,
                    KeycloakSsoCryptoRequest::PURPOSE_RELEASE,
                ],
                'status IN' => [
                    KeycloakSsoCryptoRequest::STATUS_PENDING_OIDC,
                    KeycloakSsoCryptoRequest::STATUS_OIDC_VERIFIED,
                    KeycloakSsoCryptoRequest::STATUS_PROCESSING,
                ],
            ])->orderByAsc('id')->epilog('FOR UPDATE')->all();
            $requestIds = [];
            foreach ($requestRows as $request) {
                $requestIds[] = (string)$request->get('id');
            }

            $now = DateTime::now();
            if ($requestIds !== []) {
                $transactions->find()->select(['id'])->where([
                    'crypto_request_id IN' => $requestIds,
                    'status IN' => [
                        KeycloakSsoTransaction::STATUS_PENDING,
                        KeycloakSsoTransaction::STATUS_PROCESSING,
                        KeycloakSsoTransaction::STATUS_SUCCEEDED,
                        KeycloakSsoTransaction::STATUS_CRYPTO_PROCESSING,
                    ],
                ])->orderByAsc('id')->epilog('FOR UPDATE')->all()->toList();
                $transactions->updateAll([
                    'status' => KeycloakSsoTransaction::STATUS_FAILED,
                    'result_token_hash' => null,
                    'result_expires' => null,
                    'pkce_verifier_ciphertext' => null,
                    'link_identity_ciphertext' => null,
                    'failure_code' => 'enrollment_revoked',
                    'modified' => $now,
                ], [
                    'crypto_request_id IN' => $requestIds,
                    'status IN' => [
                        KeycloakSsoTransaction::STATUS_PENDING,
                        KeycloakSsoTransaction::STATUS_PROCESSING,
                        KeycloakSsoTransaction::STATUS_SUCCEEDED,
                        KeycloakSsoTransaction::STATUS_CRYPTO_PROCESSING,
                    ],
                ]);
                $requests->updateAll([
                    'status' => KeycloakSsoCryptoRequest::STATUS_FAILED,
                    'request_ciphertext' => null,
                    'client_nonce_hash' => null,
                    'modified' => $now,
                ], [
                    'id IN' => $requestIds,
                    'status IN' => [
                        KeycloakSsoCryptoRequest::STATUS_PENDING_OIDC,
                        KeycloakSsoCryptoRequest::STATUS_OIDC_VERIFIED,
                        KeycloakSsoCryptoRequest::STATUS_PROCESSING,
                    ],
                ]);
            }

            foreach ($activeEnrollmentIds as $enrollmentId) {
                $enrollments->updateAll([
                    'status' => KeycloakSsoCryptoEnrollment::STATUS_REVOKED,
                    'revoked' => $now,
                    'server_share_ciphertext' => base64_encode(random_bytes(48)),
                    'server_share_nonce' => base64_encode(random_bytes(24)),
                    'server_share_key_id' => 'revoked',
                    'modified' => $now,
                ], [
                    'id' => $enrollmentId,
                    'status' => KeycloakSsoCryptoEnrollment::STATUS_ACTIVE,
                    'revoked IS' => null,
                ]);
            }

            sort($clientEnrollmentIds, SORT_STRING);

            return array_values(array_unique($clientEnrollmentIds));
        });
    }
}
