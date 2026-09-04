<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Controller;

use App\Model\Entity\User;
use App\Test\Factory\AuthenticationTokenFactory;
use App\Test\Factory\UserFactory;
use App\Utility\UuidFactory;
use Cake\I18n\DateTime;
use Cake\ORM\TableRegistry;
use Mdanter\Ecc\Serializer\Signature\DerSignatureSerializer;
use Mdanter\Ecc\Serializer\Signature\IEEEP1363Serializer;
use OpenSSLAsymmetricKey;
use ParagonIE\HPKE\Factory;
use Passbolt\KeycloakSso\Cryptography\HpkeReleaseService;
use Passbolt\KeycloakSso\Cryptography\ProfileSigningKeyVerifier;
use Passbolt\KeycloakSso\Cryptography\Protocol\CborProtocolV1;
use Passbolt\KeycloakSso\Cryptography\ServerShareProtector;
use Passbolt\KeycloakSso\Error\Exception\CryptoSsoException;
use Passbolt\KeycloakSso\Model\Dto\CryptoConfigurationDto;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;
use Passbolt\KeycloakSso\Model\Dto\PendingIdentityLink;
use Passbolt\KeycloakSso\Model\Dto\ValidatedOidcIdentity;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoCryptoEnrollment;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoCryptoRequest;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction;
use Passbolt\KeycloakSso\Service\Crypto\CryptoOidcProofService;
use Passbolt\KeycloakSso\Service\Crypto\CryptoReleaseService;
use Passbolt\KeycloakSso\Service\Crypto\CryptoResultClaimService;
use Passbolt\KeycloakSso\Service\Crypto\RevokeCryptoEnrollmentsService;
use Passbolt\KeycloakSso\Service\Identity\IdentityLinkPersistenceService;
use Passbolt\KeycloakSso\Service\Transaction\ClaimOidcTransactionService;
use Passbolt\KeycloakSso\Service\Transaction\CreateOidcTransactionService;
use Passbolt\KeycloakSso\Service\Transaction\TransactionSecretProtector;
use Passbolt\KeycloakSso\Test\Lib\KeycloakSsoIntegrationTestCase;

final class CryptoReleaseAuthenticationBoundaryTest extends KeycloakSsoIntegrationTestCase
{
    public function testSuccessfulOidcAndServerShareReleaseStillDoNotAuthenticatePassbolt(): void
    {
        $tokenCount = AuthenticationTokenFactory::count();
        $fixture = $this->releaseFixture();

        $package = $fixture['service']->release($fixture['token'], [
            'request_id' => $fixture['request_id'],
            'signature' => $this->sign($fixture['signing_key'], $fixture['release_transcript']),
        ]);
        $sealed = base64_decode($package['enc'], true) . base64_decode($package['ciphertext'], true);
        $this->assertSame($fixture['server_share'], $fixture['hpke_suite']->openBase(
            $fixture['hpke_private_key'],
            $sealed,
            $fixture['release_transcript'],
            CborProtocolV1::encodeBinding('context_hash', $fixture['context'])
        ));
        $this->assertEmpty($this->getSession()->read('Auth.user'));
        $this->assertSame($tokenCount, AuthenticationTokenFactory::count());

        $this->getJson('/auth/is-authenticated.json');
        $this->assertAuthenticationError();
        $this->assertEmpty($this->getSession()->read('Auth.user'));
        $this->assertSame($tokenCount, AuthenticationTokenFactory::count());

        $this->expectException(CryptoSsoException::class);
        $fixture['service']->release($fixture['token'], [
            'request_id' => $fixture['request_id'],
            'signature' => $this->sign($fixture['signing_key'], $fixture['release_transcript']),
        ]);
    }

    public function testCompletedOidcCapabilityCannotReleaseAfterPassphraseRotationRevocation(): void
    {
        $fixture = $this->releaseFixture();
        (new RevokeCryptoEnrollmentsService())->revokeAllForUser($fixture['user_id']);

        $this->expectException(CryptoSsoException::class);
        $fixture['service']->release($fixture['token'], [
            'request_id' => $fixture['request_id'],
            'signature' => $this->sign($fixture['signing_key'], $fixture['release_transcript']),
        ]);
    }

    /** @return array<string, mixed> */
    private function releaseFixture(): array
    {
        $user = UserFactory::make(['username' => 'user@example.com'])->user()->active()->notDisabled()->persist();
        self::assertInstanceOf(User::class, $user);
        $oidc = new OidcConfigurationDto(
            'https://keyclock.gobaz.ir/realms/passbolt',
            'passbolt',
            'client-secret-for-tests',
            'https://passbolt.gobaz.ir/auth/keycloak/callback',
            random_bytes(32)
        );
        $crypto = new CryptoConfigurationDto(
            'https://passbolt.gobaz.ir',
            'urn:keycloak:acr:mfa',
            [],
            'active',
            ['active' => random_bytes(32)]
        );
        $identity = (new IdentityLinkPersistenceService())->create($user->id, new PendingIdentityLink(
            $oidc->issuer,
            'immutable-subject',
            $user->username
        ));
        [$signingKey, $jwk] = $this->signingKey();
        $public = (new ProfileSigningKeyVerifier())->validatePublicJwk($jwk);
        $enrollmentId = UuidFactory::uuid();
        $clientEnrollmentId = UuidFactory::uuid();
        $context = [
            'protocol_version' => CborProtocolV1::VERSION,
            'crypto_suite' => CborProtocolV1::SUITE,
            'passbolt_origin' => $crypto->passboltOrigin,
            'user_uuid' => $user->id,
            'identity_uuid' => $identity->id,
            'enrollment_uuid' => $enrollmentId,
            'client_enrollment_uuid' => $clientEnrollmentId,
            'openpgp_fingerprint' => '0123456789ABCDEF0123456789ABCDEF01234567',
            'enrollment_public_key_thumbprint' => $public['thumbprint'],
        ];
        $serverShare = random_bytes(32);
        $shareProtector = new ServerShareProtector($crypto);
        $protected = $shareProtector->encrypt(
            $serverShare,
            CborProtocolV1::encodeBinding('release_package', $context)
        );
        $enrollment = TableRegistry::getTableLocator()
            ->get('Passbolt/KeycloakSso.KeycloakSsoCryptoEnrollments')
            ->newEmptyEntity();
        foreach (
            [
            'id' => $enrollmentId,
            'user_id' => $user->id,
            'identity_id' => $identity->id,
            'client_enrollment_uuid' => $clientEnrollmentId,
            'context_cbor' => base64_encode(CborProtocolV1::encodeContext($context)),
            'signing_public_key' => $public['canonical'],
            'signing_key_thumbprint' => $public['thumbprint'],
            'server_share_ciphertext' => $protected['ciphertext'],
            'server_share_nonce' => $protected['nonce'],
            'server_share_key_id' => $protected['keyId'],
            'client_blob_digest' => str_repeat('a', 64),
            'passbolt_key_fingerprint' => $context['openpgp_fingerprint'],
            'protocol_version' => CborProtocolV1::VERSION,
            'crypto_suite' => CborProtocolV1::SUITE,
            'status' => KeycloakSsoCryptoEnrollment::STATUS_ACTIVE,
            ] as $field => $value
        ) {
            $enrollment->set($field, $value);
        }
        TableRegistry::getTableLocator()
            ->get('Passbolt/KeycloakSso.KeycloakSsoCryptoEnrollments')
            ->saveOrFail($enrollment);

        $hpkeSuite = Factory::dhkem_p256sha256_hkdf_sha256_aes128gcm();
        [$hpkePrivateKey, $hpkePublicKey] = $hpkeSuite->kem->generateKeys();
        $clientNonce = random_bytes(32);
        $requestId = UuidFactory::uuid();
        $requestProtector = new TransactionSecretProtector($oidc->transactionEncryptionKey);
        $protectedRequest = $requestProtector->encrypt(json_encode([
            'client_nonce' => base64_encode($clientNonce),
            'hpke_recipient_public_key' => base64_encode($hpkePublicKey->bytes),
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES), $requestId . ':crypto-release');
        $request = TableRegistry::getTableLocator()
            ->get('Passbolt/KeycloakSso.KeycloakSsoCryptoRequests')
            ->newEmptyEntity();
        foreach (
            [
            'id' => $requestId,
            'purpose' => KeycloakSsoCryptoRequest::PURPOSE_RELEASE,
            'user_id' => $user->id,
            'identity_id' => $identity->id,
            'enrollment_id' => $enrollmentId,
            'request_ciphertext' => $protectedRequest,
            'client_nonce_hash' => hash('sha256', $clientNonce),
            'status' => KeycloakSsoCryptoRequest::STATUS_PENDING_OIDC,
            'expires' => DateTime::now()->addMinutes(5),
            ] as $field => $value
        ) {
            $request->set($field, $value);
        }
        TableRegistry::getTableLocator()->get('Passbolt/KeycloakSso.KeycloakSsoCryptoRequests')->saveOrFail($request);
        $created = (new CreateOidcTransactionService($requestProtector))->create(
            $oidc->issuer,
            $oidc->clientId,
            $oidc->redirectUri,
            $oidc->configurationHash(),
            OidcConfigurationDto::TRANSACTION_TTL_SECONDS,
            KeycloakSsoTransaction::PURPOSE_CRYPTO_RELEASE,
            $user->id,
            $requestId
        );
        $transactions = new ClaimOidcTransactionService($requestProtector);
        $claimed = $transactions->claim($created->state, $created->browserBinding, $oidc->configurationHash());
        (new CryptoOidcProofService($crypto))->verify(
            $claimed['transaction'],
            new ValidatedOidcIdentity('immutable-subject', $user->username, time(), $crypto->requiredAcr)
        );
        $token = $transactions->succeed($created->id, OidcConfigurationDto::CRYPTO_RESULT_TTL_SECONDS);
        $releaseTranscript = CborProtocolV1::encodeReleasePackageTranscript(
            $context,
            base64_encode($clientNonce),
            base64_encode($hpkePublicKey->bytes),
            $requestId
        );

        return [
            'service' => new CryptoReleaseService(
                new CryptoResultClaimService(),
                $requestProtector,
                $shareProtector,
                new HpkeReleaseService(),
                new ProfileSigningKeyVerifier()
            ),
            'token' => $token,
            'request_id' => $requestId,
            'release_transcript' => $releaseTranscript,
            'signing_key' => $signingKey,
            'server_share' => $serverShare,
            'hpke_suite' => $hpkeSuite,
            'hpke_private_key' => $hpkePrivateKey,
            'context' => $context,
            'user_id' => $user->id,
        ];
    }

    /** @return array{0: \OpenSSLAsymmetricKey, 1: string} */
    private function signingKey(): array
    {
        $privateKey = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        $details = openssl_pkey_get_details($privateKey);
        $jwk = json_encode([
            'crv' => 'P-256',
            'ext' => true,
            'key_ops' => ['verify'],
            'kty' => 'EC',
            'x' => $this->base64Url($details['ec']['x']),
            'y' => $this->base64Url($details['ec']['y']),
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

        return [$privateKey, $jwk];
    }

    private function sign(OpenSSLAsymmetricKey $privateKey, string $message): string
    {
        openssl_sign($message, $der, $privateKey, OPENSSL_ALGO_SHA256);
        $signature = (new IEEEP1363Serializer())->serialize(
            (new DerSignatureSerializer())->parse($der),
            256
        );

        return base64_encode($signature);
    }

    private function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
