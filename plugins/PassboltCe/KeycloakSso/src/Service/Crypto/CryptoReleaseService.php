<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Crypto;

use Cake\Datasource\ConnectionManager;
use Cake\I18n\DateTime;
use Cake\ORM\Locator\LocatorAwareTrait;
use JsonException;
use Passbolt\KeycloakSso\Cryptography\HpkeReleaseService;
use Passbolt\KeycloakSso\Cryptography\ProfileSigningKeyVerifier;
use Passbolt\KeycloakSso\Cryptography\Protocol\CborProtocolV1;
use Passbolt\KeycloakSso\Cryptography\ServerShareProtector;
use Passbolt\KeycloakSso\Error\Exception\CryptoSsoException;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoCryptoEnrollment;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoCryptoRequest;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction;
use Passbolt\KeycloakSso\Service\Transaction\TransactionSecretProtector;
use SensitiveParameter;
use Throwable;

final class CryptoReleaseService
{
    use LocatorAwareTrait;

    /**
     * Construct the one-time server-share release service.
     */
    public function __construct(
        private readonly CryptoResultClaimService $claims,
        private readonly TransactionSecretProtector $requestProtector,
        private readonly ServerShareProtector $shares,
        private readonly HpkeReleaseService $hpke,
        private readonly ProfileSigningKeyVerifier $profileSignatures,
        private readonly RotationBarrierService $rotationBarrier,
    ) {
    }

    /** @return array{enc: string, ciphertext: string, context_hash: string} */
    public function release(#[SensitiveParameter]
    string $resultToken, #[SensitiveParameter]
    array $input): array
    {
        $claimed = $this->claims->claim($resultToken, KeycloakSsoCryptoRequest::PURPOSE_RELEASE);
        $transaction = $claimed['transaction'];
        $request = $claimed['request'];
        try {
            /** @var \Cake\Database\Connection $connection */
            $connection = ConnectionManager::get('default');

            return $connection->transactional(
                fn (): array => $this->releaseClaimed($transaction, $request, $input)
            );
        } catch (Throwable $exception) {
            $this->claims->fail($transaction->id, $request->id);
            if ($exception instanceof CryptoSsoException) {
                throw $exception;
            }
            throw new CryptoSsoException('release_failed');
        }
    }

    /**
     * @param array<string, mixed> $input
     * @return array{enc: string, ciphertext: string, context_hash: string}
     */
    private function releaseClaimed(
        KeycloakSsoTransaction $transaction,
        KeycloakSsoCryptoRequest $request,
        array $input
    ): array {
        $this->rotationBarrier->lockActiveUser($request->user_id);
        $this->rotationBarrier->assertInactive($request->user_id);
        /** @var \Passbolt\KeycloakSso\Model\Entity\KeycloakSsoIdentity|null $identity */
        $identity = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoIdentities')->find()->where([
            'id' => $request->identity_id,
            'user_id' => $request->user_id,
            'issuer' => $transaction->issuer,
        ])->epilog('FOR UPDATE')->first();
        /** @var \Passbolt\KeycloakSso\Model\Entity\KeycloakSsoCryptoEnrollment|null $enrollment */
        $enrollment = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoCryptoEnrollments')->find()->where([
            'id' => $request->enrollment_id,
            'user_id' => $request->user_id,
            'identity_id' => $request->identity_id,
            'status' => KeycloakSsoCryptoEnrollment::STATUS_ACTIVE,
            'revoked IS' => null,
        ])->epilog('FOR UPDATE')->first();
        if ($enrollment === null || $identity === null) {
            throw new CryptoSsoException('release_owner_unavailable');
        }
        $currentGpgkey = $this->fetchTable('Gpgkeys')->find()->where([
            'user_id' => $enrollment->get('user_id'),
            'fingerprint' => $enrollment->get('passbolt_key_fingerprint'),
            'deleted' => false,
        ])->first();
        if ($currentGpgkey === null) {
            throw new CryptoSsoException('release_owner_unavailable');
        }
        $contextBytes = base64_decode((string)$enrollment->get('context_cbor'), true);
        if (
            $contextBytes === false ||
            !hash_equals(base64_encode($contextBytes), (string)$enrollment->get('context_cbor'))
        ) {
            throw new CryptoSsoException('enrollment_context_invalid');
        }
        $context = CborProtocolV1::decodeContext($contextBytes);
        $requestId = $input['request_id'] ?? null;
        $releaseSignature = $input['signature'] ?? null;
        if (
            !is_string($requestId) || !hash_equals($request->id, $requestId) ||
            !is_string($releaseSignature) || strlen($releaseSignature) > 128
        ) {
            throw new CryptoSsoException('signed_release_request_invalid');
        }
        $protectedRequest = $this->requestProtector->decrypt(
            (string)$request->request_ciphertext,
            $request->id . ':crypto-release'
        );
        try {
            $releaseRequest = json_decode($protectedRequest, true, 4, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new CryptoSsoException('release_request_invalid');
        }
        if (
            !is_array($releaseRequest) ||
            array_keys($releaseRequest) !== ['client_nonce', 'hpke_recipient_public_key'] ||
            !is_string($releaseRequest['client_nonce']) ||
            !is_string($releaseRequest['hpke_recipient_public_key'])
        ) {
            throw new CryptoSsoException('release_request_invalid');
        }
        $clientNonce = base64_decode($releaseRequest['client_nonce'], true);
        $recipient = base64_decode($releaseRequest['hpke_recipient_public_key'], true);
        if (
            $clientNonce === false || strlen($clientNonce) !== 32 ||
            $recipient === false || strlen($recipient) !== 65 ||
            !hash_equals((string)$request->client_nonce_hash, hash('sha256', $clientNonce))
        ) {
            throw new CryptoSsoException('release_request_invalid');
        }
        $releaseAad = CborProtocolV1::encodeReleasePackageTranscript(
            $context,
            base64_encode($clientNonce),
            base64_encode($recipient),
            $request->id
        );
        $this->profileSignatures->verify(
            (string)$enrollment->get('signing_public_key'),
            $releaseAad,
            $releaseSignature
        );
        $serverShare = $this->shares->decrypt(
            (string)$enrollment->get('server_share_ciphertext'),
            (string)$enrollment->get('server_share_nonce'),
            (string)$enrollment->get('server_share_key_id'),
            CborProtocolV1::encodeBinding('release_package', $context)
        );
        try {
            $package = $this->hpke->seal(
                $serverShare,
                base64_encode($recipient),
                $releaseAad,
                CborProtocolV1::encodeBinding('context_hash', $context)
            );
        } finally {
            sodium_memzero($serverShare);
        }
        $this->claims->consume($transaction->id, $request->id);
        $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoCryptoEnrollments')->updateAll([
            'last_used' => DateTime::now(),
            'modified' => DateTime::now(),
        ], ['id' => $enrollment->id, 'status' => KeycloakSsoCryptoEnrollment::STATUS_ACTIVE]);

        return $package + ['context_hash' => CborProtocolV1::contextHash($context)];
    }
}
