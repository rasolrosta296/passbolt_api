<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Crypto;

use Cake\Datasource\ConnectionManager;
use Cake\ORM\Locator\LocatorAwareTrait;
use Passbolt\KeycloakSso\Cryptography\OpenPgpEnrollmentProofVerifier;
use Passbolt\KeycloakSso\Cryptography\ProfileSigningKeyVerifier;
use Passbolt\KeycloakSso\Cryptography\Protocol\CborProtocolV1;
use Passbolt\KeycloakSso\Cryptography\ServerShareProtector;
use Passbolt\KeycloakSso\Error\Exception\CryptoSsoException;
use Passbolt\KeycloakSso\Model\Dto\CryptoConfigurationDto;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoCryptoEnrollment;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoCryptoRequest;
use SensitiveParameter;
use Throwable;

final class CryptoEnrollmentService
{
    use LocatorAwareTrait;

    /**
     * Construct the browser-profile enrollment service.
     */
    public function __construct(
        private readonly CryptoConfigurationDto $configuration,
        private readonly CryptoResultClaimService $claims,
        private readonly ProfileSigningKeyVerifier $profileSignatures,
        private readonly OpenPgpEnrollmentProofVerifier $openPgpProofs,
        private readonly ServerShareProtector $shares,
        private readonly RotationBarrierService $rotationBarrier,
    ) {
    }

    /** @param array<string, mixed> $input */
    public function enroll(#[SensitiveParameter]
    string $resultToken, string $authenticatedUserId, array $input): KeycloakSsoCryptoEnrollment
    {
        $claimed = $this->claims->claim($resultToken, KeycloakSsoCryptoRequest::PURPOSE_ENROLLMENT);
        $transaction = $claimed['transaction'];
        $request = $claimed['request'];
        try {
            if (
                !hash_equals($authenticatedUserId, $request->user_id) ||
                !hash_equals((string)$transaction->requested_user_id, $authenticatedUserId)
            ) {
                throw new CryptoSsoException('authenticated_user_mismatch');
            }
            $contextBytes = $this->base64($input, 'context_cbor', CborProtocolV1::MAX_CONTEXT_BYTES);
            $context = CborProtocolV1::decodeContext($contextBytes);
            $serverShare = $this->base64($input, 'server_share', 32, 32);
            $clientBlobDigest = $this->hex($input, 'client_blob_digest', 64);
            $fingerprint = $this->hex($input, 'openpgp_fingerprint', 40, true);
            $clientEnrollmentId = $this->string($input, 'client_enrollment_uuid', 36);
            $publicJwk = $this->string($input, 'signing_public_key', 2048);
            $claimedThumbprint = $this->string($input, 'signing_key_thumbprint', 43);
            $openPgpSignature = $this->string($input, 'openpgp_transcript_signature', 32_768);
            $validatedKey = $this->profileSignatures->validatePublicJwk($publicJwk);

            if (
                !hash_equals($request->enrollment_id, $context['enrollment_uuid']) ||
                !hash_equals($request->user_id, $context['user_uuid']) ||
                !hash_equals($request->identity_id, $context['identity_uuid']) ||
                !hash_equals($clientEnrollmentId, $context['client_enrollment_uuid']) ||
                !hash_equals($fingerprint, $context['openpgp_fingerprint']) ||
                !hash_equals($this->configuration->passboltOrigin, $context['passbolt_origin']) ||
                !hash_equals($validatedKey['thumbprint'], $claimedThumbprint) ||
                !hash_equals($validatedKey['thumbprint'], $context['enrollment_public_key_thumbprint'])
            ) {
                throw new CryptoSsoException('enrollment_context_mismatch');
            }
            $shareDigest = hash('sha256', $serverShare);
            $transcript = CborProtocolV1::encodeEnrollmentTranscript($context, $clientBlobDigest, $shareDigest);
            $this->openPgpProofs->verify($authenticatedUserId, $fingerprint, $transcript, $openPgpSignature);

            $shareAad = CborProtocolV1::encodeBinding('release_package', $context);
            $protected = $this->shares->encrypt($serverShare, $shareAad);
            sodium_memzero($serverShare);
            $table = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoCryptoEnrollments');
            $entity = $table->newEmptyEntity();
            foreach (
                [
                'id' => $request->enrollment_id,
                'user_id' => $authenticatedUserId,
                'identity_id' => $request->identity_id,
                'client_enrollment_uuid' => $clientEnrollmentId,
                'context_cbor' => base64_encode($contextBytes),
                'signing_public_key' => $validatedKey['canonical'],
                'signing_key_thumbprint' => $validatedKey['thumbprint'],
                'server_share_ciphertext' => $protected['ciphertext'],
                'server_share_nonce' => $protected['nonce'],
                'server_share_key_id' => $protected['keyId'],
                'client_blob_digest' => $clientBlobDigest,
                'passbolt_key_fingerprint' => $fingerprint,
                'protocol_version' => CborProtocolV1::VERSION,
                'crypto_suite' => CborProtocolV1::SUITE,
                'status' => KeycloakSsoCryptoEnrollment::STATUS_ACTIVE,
                ] as $field => $value
            ) {
                $entity->set($field, $value);
            }
            /** @var \Cake\Database\Connection $connection */
            $connection = ConnectionManager::get('default');
            $connection->transactional(function () use (
                $table,
                $entity,
                $transaction,
                $request,
                $authenticatedUserId
            ): void {
                $this->rotationBarrier->lockActiveUser($authenticatedUserId);
                $identity = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoIdentities')->find()->where([
                    'id' => $request->identity_id,
                    'user_id' => $authenticatedUserId,
                    'issuer' => $transaction->issuer,
                ])->epilog('FOR UPDATE')->first();
                if ($identity === null) {
                    throw new CryptoSsoException('enrollment_owner_unavailable');
                }
                $this->rotationBarrier->assertInactive($authenticatedUserId);
                if (!$table->save($entity) || !($entity instanceof KeycloakSsoCryptoEnrollment)) {
                    throw new CryptoSsoException('enrollment_persistence_failed');
                }
                $this->claims->consume($transaction->id, $request->id);
            });

            return $entity;
        } catch (Throwable $exception) {
            if (isset($serverShare) && is_string($serverShare) && $serverShare !== '') {
                sodium_memzero($serverShare);
            }
            $this->claims->fail($transaction->id, $request->id);
            if ($exception instanceof CryptoSsoException) {
                throw $exception;
            }
            throw new CryptoSsoException('enrollment_failed');
        }
    }

    /** @param array<string, mixed> $input */
    private function string(array $input, string $field, int $max): string
    {
        $value = $input[$field] ?? null;
        if (!is_string($value) || $value === '' || strlen($value) > $max) {
            throw new CryptoSsoException('enrollment_input_invalid');
        }

        return $value;
    }

    /** @param array<string, mixed> $input */
    private function base64(array $input, string $field, int $max, ?int $exact = null): string
    {
        $encoded = $this->string($input, $field, (int)ceil($max * 4 / 3) + 4);
        $decoded = base64_decode($encoded, true);
        if (
            $decoded === false || strlen($decoded) > $max || ($exact !== null && strlen($decoded) !== $exact) ||
            !hash_equals(base64_encode($decoded), $encoded)
        ) {
            throw new CryptoSsoException('enrollment_input_invalid');
        }

        return $decoded;
    }

    /** @param array<string, mixed> $input */
    private function hex(array $input, string $field, int $length, bool $uppercase = false): string
    {
        $value = $this->string($input, $field, $length);
        $pattern = $uppercase ? '/^[0-9A-F]+$/D' : '/^[0-9a-f]+$/D';
        if (strlen($value) !== $length || preg_match($pattern, $value) !== 1) {
            throw new CryptoSsoException('enrollment_input_invalid');
        }

        return $value;
    }
}
