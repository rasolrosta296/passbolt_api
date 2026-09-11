<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Service\Crypto;

use App\Model\Entity\Gpgkey;
use App\Model\Entity\User;
use App\Test\Factory\AuthenticationTokenFactory;
use App\Test\Factory\GpgkeyFactory;
use App\Test\Factory\UserFactory;
use App\Test\Lib\Utility\Gpg\GpgAdaSetupTrait;
use App\Utility\UuidFactory;
use Cake\I18n\DateTime;
use Cake\ORM\TableRegistry;
use Passbolt\KeycloakSso\Cryptography\OpenPgpEnrollmentProofVerifier;
use Passbolt\KeycloakSso\Cryptography\ProfileSigningKeyVerifier;
use Passbolt\KeycloakSso\Cryptography\Protocol\CborProtocolV1;
use Passbolt\KeycloakSso\Cryptography\ServerShareProtector;
use Passbolt\KeycloakSso\Error\Exception\CryptoSsoException;
use Passbolt\KeycloakSso\Model\Dto\CryptoConfigurationDto;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;
use Passbolt\KeycloakSso\Model\Dto\PendingIdentityLink;
use Passbolt\KeycloakSso\Model\Dto\ValidatedOidcIdentity;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoCryptoRequest;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction;
use Passbolt\KeycloakSso\Service\Crypto\CryptoEnrollmentService;
use Passbolt\KeycloakSso\Service\Crypto\CryptoOidcProofService;
use Passbolt\KeycloakSso\Service\Crypto\CryptoResultClaimService;
use Passbolt\KeycloakSso\Service\Crypto\RevokeCryptoEnrollmentsService;
use Passbolt\KeycloakSso\Service\Crypto\RotationBarrierService;
use Passbolt\KeycloakSso\Service\Identity\IdentityLinkPersistenceService;
use Passbolt\KeycloakSso\Service\Transaction\ClaimOidcTransactionService;
use Passbolt\KeycloakSso\Service\Transaction\CreateOidcTransactionService;
use Passbolt\KeycloakSso\Service\Transaction\TransactionSecretProtector;
use Passbolt\KeycloakSso\Test\Lib\KeycloakSsoIntegrationTestCase;

final class CryptoEnrollmentServiceTest extends KeycloakSsoIntegrationTestCase
{
    use GpgAdaSetupTrait;

    public function setUp(): void
    {
        parent::setUp();
        $this->gpgSetup();
    }

    public function testEnrollmentPersistsOnlyProtectedServerShareAndDoesNotAuthenticate(): void
    {
        $_SESSION = [];
        $authenticationTokenCount = AuthenticationTokenFactory::count();
        $fixture = $this->fixture();

        $enrollment = $fixture['service']->enroll(
            $fixture['result_token'],
            $fixture['user_id'],
            $fixture['input']
        );

        $this->assertSame($fixture['enrollment_id'], $enrollment->id);
        $this->assertNotSame(base64_encode($fixture['server_share']), $enrollment->server_share_ciphertext);
        $this->assertSame(48, strlen((string)base64_decode($enrollment->server_share_ciphertext, true)));
        $this->assertSame(24, strlen((string)base64_decode($enrollment->server_share_nonce, true)));
        $this->assertSame($fixture['crypto']->activeServerShareKeyId, $enrollment->server_share_key_id);
        $this->assertSame(
            $fixture['server_share'],
            (new ServerShareProtector($fixture['crypto']))->decrypt(
                $enrollment->server_share_ciphertext,
                $enrollment->server_share_nonce,
                $enrollment->server_share_key_id,
                CborProtocolV1::encodeBinding('release_package', $fixture['context'])
            )
        );
        /** @var \Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction $transaction */
        $transaction = TableRegistry::getTableLocator()
            ->get('Passbolt/KeycloakSso.KeycloakSsoTransactions')
            ->get($fixture['transaction_id']);
        $this->assertSame(KeycloakSsoTransaction::STATUS_RESULT_CONSUMED, $transaction->status);
        $this->assertNull($transaction->result_token_hash);
        $this->assertEmpty($this->getSession()->read('Auth.user'));
        $this->assertSame($authenticationTokenCount, AuthenticationTokenFactory::count());
    }

    public function testEnrollmentRejectsAuthenticatedUserMismatch(): void
    {
        $fixture = $this->fixture();
        $otherUser = UserFactory::make()->user()->active()->notDisabled()->persist();
        self::assertInstanceOf(User::class, $otherUser);

        try {
            $fixture['service']->enroll($fixture['result_token'], $otherUser->id, $fixture['input']);
            $this->fail('An OIDC proof belonging to another user must not create an enrollment.');
        } catch (CryptoSsoException $exception) {
            $this->assertSame('authenticated_user_mismatch', $exception->reasonCode());
        }
        $this->assertSame(0, TableRegistry::getTableLocator()
            ->get('Passbolt/KeycloakSso.KeycloakSsoCryptoEnrollments')->find()->count());
    }

    public function testEnrollmentRejectsInvalidOpenPgpTranscriptProof(): void
    {
        $fixture = $this->fixture();
        $fixture['input']['openpgp_transcript_signature'] = 'invalid-signature';

        try {
            $fixture['service']->enroll($fixture['result_token'], $fixture['user_id'], $fixture['input']);
            $this->fail('Enrollment must require proof from the existing Passbolt OpenPGP private key.');
        } catch (CryptoSsoException $exception) {
            $this->assertSame('openpgp_enrollment_proof_invalid', $exception->reasonCode());
        }
        $this->assertSame(0, TableRegistry::getTableLocator()
            ->get('Passbolt/KeycloakSso.KeycloakSsoCryptoEnrollments')->find()->count());
    }

    /** @return array<string, mixed> */
    private function fixture(): array
    {
        $user = UserFactory::make(['username' => 'user@example.com'])->user()->active()->notDisabled()->persist();
        self::assertInstanceOf(User::class, $user);
        $gpgkey = GpgkeyFactory::make()->withAdaKey()->setField('user_id', $user->id)->persist();
        self::assertInstanceOf(Gpgkey::class, $gpgkey);
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
        [, $signingJwk] = $this->signingKey();
        $profileKey = (new ProfileSigningKeyVerifier())->validatePublicJwk($signingJwk);
        $enrollmentId = UuidFactory::uuid();
        $requestId = UuidFactory::uuid();
        $request = TableRegistry::getTableLocator()
            ->get('Passbolt/KeycloakSso.KeycloakSsoCryptoRequests')
            ->newEmptyEntity();
        foreach (
            [
            'id' => $requestId,
            'purpose' => KeycloakSsoCryptoRequest::PURPOSE_ENROLLMENT,
            'user_id' => $user->id,
            'identity_id' => $identity->id,
            'enrollment_id' => $enrollmentId,
            'status' => KeycloakSsoCryptoRequest::STATUS_PENDING_OIDC,
            'expires' => DateTime::now()->addMinutes(5),
            ] as $field => $value
        ) {
            $request->set($field, $value);
        }
        TableRegistry::getTableLocator()
            ->get('Passbolt/KeycloakSso.KeycloakSsoCryptoRequests')
            ->saveOrFail($request);
        $protector = new TransactionSecretProtector($oidc->transactionEncryptionKey);
        $created = (new CreateOidcTransactionService($protector))->create(
            $oidc->issuer,
            $oidc->clientId,
            $oidc->redirectUri,
            $oidc->configurationHash(),
            OidcConfigurationDto::TRANSACTION_TTL_SECONDS,
            KeycloakSsoTransaction::PURPOSE_CRYPTO_ENROLLMENT,
            $user->id,
            $requestId
        );
        $transactions = new ClaimOidcTransactionService($protector);
        $claimed = $transactions->claim($created->state, $created->browserBinding, $oidc->configurationHash());
        (new CryptoOidcProofService($crypto))->verify(
            $claimed['transaction'],
            new ValidatedOidcIdentity('immutable-subject', $user->username, time(), $crypto->requiredAcr)
        );
        $resultToken = $transactions->succeed($created->id, OidcConfigurationDto::CRYPTO_RESULT_TTL_SECONDS);

        $clientEnrollmentId = UuidFactory::uuid();
        $context = [
            'protocol_version' => CborProtocolV1::VERSION,
            'crypto_suite' => CborProtocolV1::SUITE,
            'passbolt_origin' => $crypto->passboltOrigin,
            'user_uuid' => $user->id,
            'identity_uuid' => $identity->id,
            'enrollment_uuid' => $enrollmentId,
            'client_enrollment_uuid' => $clientEnrollmentId,
            'openpgp_fingerprint' => $gpgkey->fingerprint,
            'enrollment_public_key_thumbprint' => $profileKey['thumbprint'],
        ];
        $serverShare = random_bytes(32);
        $clientBlobDigest = hash('sha256', random_bytes(96));
        $transcript = CborProtocolV1::encodeEnrollmentTranscript(
            $context,
            $clientBlobDigest,
            hash('sha256', $serverShare)
        );
        $this->gpg->setSignKeyFromFingerprint($gpgkey->fingerprint, '');
        $openPgpSignature = $this->gpg->sign(rtrim(strtr(base64_encode($transcript), '+/', '-_'), '='));
        $shareProtector = new ServerShareProtector($crypto);

        return [
            'service' => new CryptoEnrollmentService(
                $crypto,
                new CryptoResultClaimService(),
                new ProfileSigningKeyVerifier(),
                new OpenPgpEnrollmentProofVerifier(),
                $shareProtector,
                new RotationBarrierService($protector, new RevokeCryptoEnrollmentsService())
            ),
            'input' => [
                'context_cbor' => base64_encode(CborProtocolV1::encodeContext($context)),
                'server_share' => base64_encode($serverShare),
                'client_blob_digest' => $clientBlobDigest,
                'openpgp_fingerprint' => $gpgkey->fingerprint,
                'client_enrollment_uuid' => $clientEnrollmentId,
                'signing_public_key' => $profileKey['canonical'],
                'signing_key_thumbprint' => $profileKey['thumbprint'],
                'openpgp_transcript_signature' => $openPgpSignature,
            ],
            'crypto' => $crypto,
            'context' => $context,
            'server_share' => $serverShare,
            'result_token' => $resultToken,
            'transaction_id' => $created->id,
            'enrollment_id' => $enrollmentId,
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
            'x' => $this->base64Url(str_pad($details['ec']['x'], 32, "\0", STR_PAD_LEFT)),
            'y' => $this->base64Url(str_pad($details['ec']['y'], 32, "\0", STR_PAD_LEFT)),
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

        return [$privateKey, $jwk];
    }

    private function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
