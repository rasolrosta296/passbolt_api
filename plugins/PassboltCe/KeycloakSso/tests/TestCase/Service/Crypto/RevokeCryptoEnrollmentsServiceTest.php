<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Service\Crypto;

use App\Model\Entity\User;
use App\Test\Factory\UserFactory;
use App\Utility\UuidFactory;
use Cake\I18n\DateTime;
use Cake\ORM\TableRegistry;
use Passbolt\KeycloakSso\Cryptography\Protocol\CborProtocolV1;
use Passbolt\KeycloakSso\Model\Dto\PendingIdentityLink;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoCryptoEnrollment;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoCryptoRequest;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction;
use Passbolt\KeycloakSso\Service\Crypto\RevokeCryptoEnrollmentsService;
use Passbolt\KeycloakSso\Service\Identity\IdentityLinkPersistenceService;
use Passbolt\KeycloakSso\Test\Lib\KeycloakSsoIntegrationTestCase;

final class RevokeCryptoEnrollmentsServiceTest extends KeycloakSsoIntegrationTestCase
{
    private const ISSUER = 'https://keyclock.gobaz.ir/realms/passbolt';

    public function testRevocationErasesSharesAndInvalidatesEveryOutstandingReleaseState(): void
    {
        [$user, $identityId, $enrollmentId, $clientEnrollmentId] = $this->enrollmentFixture();
        $pendingRequest = $this->releaseRequest($user->id, $identityId, $enrollmentId, 'pending_oidc');
        $verifiedRequest = $this->releaseRequest($user->id, $identityId, $enrollmentId, 'oidc_verified');
        $processingRequest = $this->releaseRequest($user->id, $identityId, $enrollmentId, 'processing');
        $this->transaction($user->id, $pendingRequest, KeycloakSsoTransaction::STATUS_PROCESSING);
        $this->transaction($user->id, $verifiedRequest, KeycloakSsoTransaction::STATUS_SUCCEEDED);
        $this->transaction($user->id, $processingRequest, KeycloakSsoTransaction::STATUS_CRYPTO_PROCESSING);

        $clientIds = (new RevokeCryptoEnrollmentsService())->revokeAllForUser($user->id);

        $this->assertSame([$clientEnrollmentId], $clientIds);
        $enrollment = $this->enrollments()->get($enrollmentId);
        $this->assertSame(KeycloakSsoCryptoEnrollment::STATUS_REVOKED, $enrollment->get('status'));
        $this->assertNotNull($enrollment->get('revoked'));
        $this->assertSame('revoked', $enrollment->get('server_share_key_id'));
        $this->assertNotSame(base64_encode(str_repeat('S', 48)), $enrollment->get('server_share_ciphertext'));

        foreach ([$pendingRequest, $verifiedRequest, $processingRequest] as $requestId) {
            $request = $this->requests()->get($requestId);
            $this->assertSame(KeycloakSsoCryptoRequest::STATUS_FAILED, $request->get('status'));
            $this->assertNull($request->get('request_ciphertext'));
            $this->assertNull($request->get('client_nonce_hash'));
            $transaction = $this->transactions()->find()->where(['crypto_request_id' => $requestId])->firstOrFail();
            $this->assertSame(KeycloakSsoTransaction::STATUS_FAILED, $transaction->get('status'));
            $this->assertNull($transaction->get('result_token_hash'));
            $this->assertNull($transaction->get('result_expires'));
            $this->assertNull($transaction->get('pkce_verifier_ciphertext'));
            $this->assertSame('enrollment_revoked', $transaction->get('failure_code'));
        }
    }

    public function testRevocationIsIdempotentAndReturnsIdsForCleanupRetry(): void
    {
        [$user, , , $clientEnrollmentId] = $this->enrollmentFixture();
        $service = new RevokeCryptoEnrollmentsService();

        $this->assertSame([$clientEnrollmentId], $service->revokeAllForUser($user->id));
        $ciphertext = $this->enrollments()->find()->firstOrFail()->get('server_share_ciphertext');
        $this->assertSame([$clientEnrollmentId], $service->revokeAllForUser($user->id));
        $this->assertSame($ciphertext, $this->enrollments()->find()->firstOrFail()->get('server_share_ciphertext'));
    }

    public function testWrongUserCannotRevokeAnotherUsersEnrollment(): void
    {
        [$owner, , $enrollmentId] = $this->enrollmentFixture();
        $other = UserFactory::make()->user()->active()->notDisabled()->persist();
        self::assertInstanceOf(User::class, $other);

        $this->assertSame([], (new RevokeCryptoEnrollmentsService())->revokeAllForUser($other->id));
        $this->assertSame(
            KeycloakSsoCryptoEnrollment::STATUS_ACTIVE,
            $this->enrollments()->get($enrollmentId)->get('status')
        );
        $this->assertNotSame($owner->id, $other->id);
    }

    /** @return array{0: User, 1: string, 2: string, 3: string} */
    private function enrollmentFixture(): array
    {
        $user = UserFactory::make(['username' => UuidFactory::uuid() . '@example.com'])
            ->user()->active()->notDisabled()->persist();
        self::assertInstanceOf(User::class, $user);
        $identity = (new IdentityLinkPersistenceService())->create($user->id, new PendingIdentityLink(
            self::ISSUER,
            UuidFactory::uuid(),
            $user->username
        ));
        $enrollmentId = UuidFactory::uuid();
        $clientEnrollmentId = UuidFactory::uuid();
        $enrollment = $this->enrollments()->newEmptyEntity();
        foreach ([
            'id' => $enrollmentId,
            'user_id' => $user->id,
            'identity_id' => $identity->id,
            'client_enrollment_uuid' => $clientEnrollmentId,
            'context_cbor' => base64_encode('test-context'),
            'signing_public_key' => '{"kty":"EC"}',
            'signing_key_thumbprint' => str_repeat('t', 43),
            'server_share_ciphertext' => base64_encode(str_repeat('S', 48)),
            'server_share_nonce' => base64_encode(str_repeat('N', 24)),
            'server_share_key_id' => 'active',
            'client_blob_digest' => str_repeat('a', 64),
            'passbolt_key_fingerprint' => str_repeat('A', 40),
            'protocol_version' => CborProtocolV1::VERSION,
            'crypto_suite' => CborProtocolV1::SUITE,
            'status' => KeycloakSsoCryptoEnrollment::STATUS_ACTIVE,
        ] as $field => $value) {
            $enrollment->set($field, $value);
        }
        $this->enrollments()->saveOrFail($enrollment);

        return [$user, $identity->id, $enrollmentId, $clientEnrollmentId];
    }

    private function releaseRequest(string $userId, string $identityId, string $enrollmentId, string $status): string
    {
        $id = UuidFactory::uuid();
        $request = $this->requests()->newEmptyEntity();
        foreach ([
            'id' => $id,
            'purpose' => KeycloakSsoCryptoRequest::PURPOSE_RELEASE,
            'user_id' => $userId,
            'identity_id' => $identityId,
            'enrollment_id' => $enrollmentId,
            'request_ciphertext' => base64_encode('protected-request'),
            'client_nonce_hash' => hash('sha256', $id),
            'status' => $status,
            'expires' => DateTime::now()->addMinutes(5),
        ] as $field => $value) {
            $request->set($field, $value);
        }
        $this->requests()->saveOrFail($request);

        return $id;
    }

    private function transaction(string $userId, string $requestId, string $status): void
    {
        $id = UuidFactory::uuid();
        $transaction = $this->transactions()->newEmptyEntity();
        foreach ([
            'id' => $id,
            'state_hash' => hash('sha256', 'state:' . $id),
            'nonce_hash' => hash('sha256', 'nonce:' . $id),
            'browser_binding_hash' => hash('sha256', 'browser:' . $id),
            'pkce_verifier_ciphertext' => base64_encode('protected-pkce'),
            'configuration_hash' => hash('sha256', 'configuration'),
            'issuer' => self::ISSUER,
            'client_id' => 'passbolt',
            'redirect_uri' => 'https://passbolt.gobaz.ir/auth/keycloak/callback',
            'purpose' => KeycloakSsoTransaction::PURPOSE_CRYPTO_RELEASE,
            'requested_user_id' => $userId,
            'crypto_request_id' => $requestId,
            'status' => $status,
            'result_token_hash' => $status === KeycloakSsoTransaction::STATUS_SUCCEEDED
                ? hash('sha256', 'result:' . $id)
                : null,
            'result_expires' => $status === KeycloakSsoTransaction::STATUS_SUCCEEDED
                ? DateTime::now()->addMinutes(1)
                : null,
            'expires' => DateTime::now()->addMinutes(5),
        ] as $field => $value) {
            $transaction->set($field, $value);
        }
        $this->transactions()->saveOrFail($transaction);
    }

    private function enrollments(): \Cake\ORM\Table
    {
        return TableRegistry::getTableLocator()->get('Passbolt/KeycloakSso.KeycloakSsoCryptoEnrollments');
    }

    private function requests(): \Cake\ORM\Table
    {
        return TableRegistry::getTableLocator()->get('Passbolt/KeycloakSso.KeycloakSsoCryptoRequests');
    }

    private function transactions(): \Cake\ORM\Table
    {
        return TableRegistry::getTableLocator()->get('Passbolt/KeycloakSso.KeycloakSsoTransactions');
    }
}
