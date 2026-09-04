<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Crypto;

use App\Utility\UuidFactory;
use Cake\Datasource\ConnectionManager;
use Cake\I18n\DateTime;
use Cake\ORM\Locator\LocatorAwareTrait;
use Cake\Validation\Validation;
use Passbolt\KeycloakSso\Cryptography\ProfileSigningKeyVerifier;
use Passbolt\KeycloakSso\Cryptography\Protocol\CborProtocolV1;
use Passbolt\KeycloakSso\Error\Exception\CryptoSsoException;
use Passbolt\KeycloakSso\Model\Dto\CryptoAuthorizationRequest;
use Passbolt\KeycloakSso\Model\Dto\CryptoConfigurationDto;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoCryptoEnrollment;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoCryptoRequest;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction;
use Passbolt\KeycloakSso\Service\Oidc\AuthorizationRequestService;
use Passbolt\KeycloakSso\Service\Oidc\OidcDiscoveryService;
use Passbolt\KeycloakSso\Service\Transaction\CreateOidcTransactionService;
use Passbolt\KeycloakSso\Service\Transaction\TransactionSecretProtector;
use SensitiveParameter;

final class CryptoOidcAuthorizationService
{
    use LocatorAwareTrait;

    /**
     * Construct the cryptographic OIDC authorization service.
     */
    public function __construct(
        private readonly OidcConfigurationDto $oidc,
        private readonly CryptoConfigurationDto $crypto,
        private readonly OidcDiscoveryService $discovery,
        private readonly CreateOidcTransactionService $transactions,
        private readonly TransactionSecretProtector $protector,
        private readonly ProfileSigningKeyVerifier $signatures,
        private readonly RotationBarrierService $rotationBarrier,
    ) {
    }

    /**
     * Start a fresh OIDC proof for an authenticated enrollment.
     */
    public function startEnrollment(string $userId): CryptoAuthorizationRequest
    {
        $this->rotationBarrier->assertInactive($userId);
        $authorizationEndpoint = $this->discovery->get()->authorizationEndpoint;
        /** @var \Cake\Database\Connection $connection */
        $connection = ConnectionManager::get('default');

        return $connection->transactional(function () use (
            $userId,
            $authorizationEndpoint
        ): CryptoAuthorizationRequest {
            $this->rotationBarrier->lockActiveUser($userId);
            $this->rotationBarrier->assertInactive($userId);
            $identity = $this->activeIdentityForUser($userId);
            $enrollmentId = UuidFactory::uuid();
            $request = $this->createRequest(
                KeycloakSsoCryptoRequest::PURPOSE_ENROLLMENT,
                $userId,
                (string)$identity->get('id'),
                $enrollmentId,
                null,
                null
            );

            return $this->createAuthorization(
                $request->id,
                $userId,
                $enrollmentId,
                (string)$identity->get('id'),
                KeycloakSsoTransaction::PURPOSE_CRYPTO_ENROLLMENT,
                $authorizationEndpoint
            );
        });
    }

    /** @param array<string, mixed> $input */
    public function startRelease(#[SensitiveParameter]
    array $input): CryptoAuthorizationRequest
    {
        $enrollmentId = $this->requiredUuid($input, 'enrollment_id');
        $contextBytes = $this->canonicalBase64($input, 'context_cbor', CborProtocolV1::MAX_CONTEXT_BYTES);
        $context = CborProtocolV1::decodeContext($contextBytes);
        $clientNonce = $this->canonicalBase64($input, 'client_nonce', 64, 32);
        $recipient = $this->canonicalBase64($input, 'hpke_recipient_public_key', 128, 65);
        $signature = $this->requiredString($input, 'signature', 128);
        $clientBlobDigest = $this->requiredHex($input, 'client_blob_digest', 64);
        $table = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoCryptoEnrollments');
        /** @var \Passbolt\KeycloakSso\Model\Entity\KeycloakSsoCryptoEnrollment|null $candidate */
        $candidate = $table->find()->where([
            'id' => $enrollmentId,
            'status' => KeycloakSsoCryptoEnrollment::STATUS_ACTIVE,
            'revoked IS' => null,
        ])->first();
        if ($candidate === null) {
            throw new CryptoSsoException('enrollment_unavailable');
        }
        $this->rotationBarrier->assertInactive((string)$candidate->get('user_id'));
        $authorizationEndpoint = $this->discovery->get()->authorizationEndpoint;

        /** @var \Cake\Database\Connection $connection */
        $connection = ConnectionManager::get('default');

        return $connection->transactional(fn (): CryptoAuthorizationRequest => $this->startReleaseLocked(
            (string)$candidate->get('user_id'),
            $enrollmentId,
            $contextBytes,
            $context,
            $clientNonce,
            $recipient,
            $signature,
            $clientBlobDigest,
            $authorizationEndpoint
        ));
    }

    /**
     * Create a release request while serialized against passphrase rotation.
     *
     * @param array<string, string> $context
     */
    private function startReleaseLocked(
        string $userId,
        string $enrollmentId,
        string $contextBytes,
        array $context,
        string $clientNonce,
        string $recipient,
        string $signature,
        string $clientBlobDigest,
        string $authorizationEndpoint
    ): CryptoAuthorizationRequest {
        $this->rotationBarrier->lockActiveUser($userId);
        $this->rotationBarrier->assertInactive($userId);
        /** @var \Passbolt\KeycloakSso\Model\Entity\KeycloakSsoCryptoEnrollment|null $enrollment */
        $enrollment = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoCryptoEnrollments')->find()->where([
            'id' => $enrollmentId,
            'user_id' => $userId,
            'status' => KeycloakSsoCryptoEnrollment::STATUS_ACTIVE,
            'revoked IS' => null,
        ])->epilog('FOR UPDATE')->first();
        if ($enrollment === null) {
            throw new CryptoSsoException('enrollment_unavailable');
        }
        $identity = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoIdentities')->find()->where([
            'id' => $enrollment->get('identity_id'),
            'user_id' => $enrollment->get('user_id'),
            'issuer' => $this->oidc->issuer,
        ])->first();
        $user = $this->fetchTable('Users')->find('activeNotDeletedNotDisabledContainRole')->where([
            'Users.id' => $enrollment->get('user_id'),
        ])->first();
        $currentGpgkey = $this->fetchTable('Gpgkeys')->find()->where([
            'user_id' => $enrollment->get('user_id'),
            'fingerprint' => $enrollment->get('passbolt_key_fingerprint'),
            'deleted' => false,
        ])->first();
        if ($identity === null || $user === null || $currentGpgkey === null) {
            throw new CryptoSsoException('enrollment_owner_unavailable');
        }
        if (
            !hash_equals((string)$enrollment->get('context_cbor'), base64_encode($contextBytes)) ||
            !hash_equals((string)$enrollment->get('client_blob_digest'), $clientBlobDigest) ||
            !hash_equals((string)$enrollment->get('user_id'), $context['user_uuid']) ||
            !hash_equals((string)$enrollment->get('identity_id'), $context['identity_uuid']) ||
            !hash_equals((string)$enrollment->get('id'), $context['enrollment_uuid'])
        ) {
            throw new CryptoSsoException('enrollment_context_mismatch');
        }
        $transcript = CborProtocolV1::encodeDeviceLoginTranscript(
            $context,
            base64_encode($clientNonce),
            base64_encode($recipient),
            $clientBlobDigest
        );
        $this->signatures->verify((string)$enrollment->get('signing_public_key'), $transcript, $signature);
        $protectedRequest = json_encode([
            'client_nonce' => base64_encode($clientNonce),
            'hpke_recipient_public_key' => base64_encode($recipient),
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $requestId = UuidFactory::uuid();
        $request = $this->createRequest(
            KeycloakSsoCryptoRequest::PURPOSE_RELEASE,
            (string)$enrollment->get('user_id'),
            (string)$enrollment->get('identity_id'),
            $enrollmentId,
            hash('sha256', $clientNonce),
            $this->protector->encrypt($protectedRequest, $requestId . ':crypto-release'),
            $requestId
        );

        return $this->createAuthorization(
            $request->id,
            (string)$enrollment->get('user_id'),
            $enrollmentId,
            (string)$enrollment->get('identity_id'),
            KeycloakSsoTransaction::PURPOSE_CRYPTO_RELEASE,
            $authorizationEndpoint
        );
    }

    /**
     * Create a prompt=login, max_age=0 authorization transaction.
     */
    private function createAuthorization(
        string $requestId,
        string $userId,
        string $enrollmentId,
        string $identityId,
        string $purpose,
        string $authorizationEndpoint
    ): CryptoAuthorizationRequest {
        $created = $this->transactions->create(
            $this->oidc->issuer,
            $this->oidc->clientId,
            $this->oidc->redirectUri,
            $this->oidc->configurationHash(),
            OidcConfigurationDto::TRANSACTION_TTL_SECONDS,
            $purpose,
            $userId,
            $requestId
        );
        $url = AuthorizationRequestService::buildAuthorizationUrl($this->oidc, $authorizationEndpoint, $created, [
            'prompt' => 'login',
            'max_age' => '0',
            'claims' => json_encode([
                'id_token' => ['acr' => ['essential' => true, 'value' => $this->crypto->requiredAcr]],
            ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
        ]);

        return new CryptoAuthorizationRequest($url, $created->browserBinding, $requestId, $enrollmentId, $identityId);
    }

    /**
     * Resolve the configured-issuer identity linked to a user.
     */
    private function activeIdentityForUser(string $userId): object
    {
        if (!Validation::uuid($userId)) {
            throw new CryptoSsoException('passbolt_session_required');
        }
        $identity = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoIdentities')->find()->where([
            'issuer' => $this->oidc->issuer,
            'user_id' => $userId,
        ])->first();
        if ($identity === null) {
            throw new CryptoSsoException('identity_not_linked');
        }

        return $identity;
    }

    /**
     * Persist a short-lived, single-purpose cryptographic request.
     */
    private function createRequest(
        string $purpose,
        string $userId,
        string $identityId,
        string $enrollmentId,
        ?string $nonceHash,
        ?string $requestCiphertext,
        ?string $requestId = null
    ): KeycloakSsoCryptoRequest {
        $table = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoCryptoRequests');
        $entity = $table->newEmptyEntity();
        foreach (
            [
            'id' => $requestId ?? UuidFactory::uuid(),
            'purpose' => $purpose,
            'user_id' => $userId,
            'identity_id' => $identityId,
            'enrollment_id' => $enrollmentId,
            'request_ciphertext' => $requestCiphertext,
            'client_nonce_hash' => $nonceHash,
            'status' => KeycloakSsoCryptoRequest::STATUS_PENDING_OIDC,
            'expires' => DateTime::now()->addSeconds(OidcConfigurationDto::TRANSACTION_TTL_SECONDS),
            ] as $field => $value
        ) {
            $entity->set($field, $value);
        }
        if (!$table->save($entity) || !($entity instanceof KeycloakSsoCryptoRequest)) {
            throw new CryptoSsoException('crypto_request_creation_failed');
        }

        return $entity;
    }

    /** @param array<string, mixed> $input */
    private function requiredString(array $input, string $field, int $maxLength): string
    {
        $value = $input[$field] ?? null;
        if (!is_string($value) || $value === '' || strlen($value) > $maxLength) {
            throw new CryptoSsoException('request_field_invalid');
        }

        return $value;
    }

    /** @param array<string, mixed> $input */
    private function requiredUuid(array $input, string $field): string
    {
        $value = $this->requiredString($input, $field, 36);
        if (!Validation::uuid($value) || strtolower($value) !== $value) {
            throw new CryptoSsoException('request_field_invalid');
        }

        return $value;
    }

    /** @param array<string, mixed> $input */
    private function requiredHex(array $input, string $field, int $length): string
    {
        $value = $this->requiredString($input, $field, $length);
        if (strlen($value) !== $length || preg_match('/^[0-9a-f]+$/D', $value) !== 1) {
            throw new CryptoSsoException('request_field_invalid');
        }

        return $value;
    }

    /** @param array<string, mixed> $input */
    private function canonicalBase64(array $input, string $field, int $maxBytes, ?int $exactBytes = null): string
    {
        $encoded = $this->requiredString($input, $field, (int)ceil($maxBytes * 4 / 3) + 4);
        $decoded = base64_decode($encoded, true);
        if (
            $decoded === false || strlen($decoded) > $maxBytes ||
            ($exactBytes !== null && strlen($decoded) !== $exactBytes) ||
            !hash_equals(base64_encode($decoded), $encoded)
        ) {
            throw new CryptoSsoException('request_field_invalid');
        }

        return $decoded;
    }
}
