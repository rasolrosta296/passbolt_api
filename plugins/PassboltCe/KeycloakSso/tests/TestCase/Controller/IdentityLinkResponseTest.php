<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Controller;

use App\Model\Entity\User;
use App\Test\Factory\UserFactory;
use App\Utility\UuidFactory;
use Cake\ORM\Table;
use Cake\ORM\TableRegistry;
use Passbolt\KeycloakSso\Configuration\KeycloakSsoEnvironment;
use Passbolt\KeycloakSso\Configuration\OidcConfigurationService;
use Passbolt\KeycloakSso\Cryptography\Protocol\CborProtocolV1;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;
use Passbolt\KeycloakSso\Model\Dto\PendingIdentityLink;
use Passbolt\KeycloakSso\Model\Dto\ValidatedOidcIdentity;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoCryptoEnrollment;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction;
use Passbolt\KeycloakSso\Service\Identity\ExistingUserDiscoveryService;
use Passbolt\KeycloakSso\Service\Identity\IdentityLinkPersistenceService;
use Passbolt\KeycloakSso\Service\Identity\IdentityLinkProofProtector;
use Passbolt\KeycloakSso\Service\Identity\PrepareIdentityLinkService;
use Passbolt\KeycloakSso\Service\Oidc\OidcCookieService;
use Passbolt\KeycloakSso\Service\Transaction\ClaimOidcTransactionService;
use Passbolt\KeycloakSso\Service\Transaction\CreateOidcTransactionService;
use Passbolt\KeycloakSso\Service\Transaction\TransactionSecretProtector;
use Passbolt\KeycloakSso\Test\Lib\KeycloakSsoIntegrationTestCase;

final class IdentityLinkResponseTest extends KeycloakSsoIntegrationTestCase
{
    /**
     * @var array<string, string|false>
     */
    private array $previousEnvironment = [];

    public function setUp(): void
    {
        parent::setUp();
        foreach ($this->environment() as $name => $value) {
            $this->previousEnvironment[$name] = getenv($name);
            putenv($name . '=' . $value);
        }
    }

    public function tearDown(): void
    {
        foreach ($this->previousEnvironment as $name => $value) {
            putenv($value === false ? $name : $name . '=' . $value);
        }
        parent::tearDown();
    }

    public function testValidConfirmationUsesPrgAfterPersistingAndConsumingProof(): void
    {
        $user = $this->activeUser('linked@example.com');
        [$token, $transactionId] = $this->prepareResult($user, 'immutable-subject', $user->username);
        $this->logInAs($user);
        $this->cookie(OidcCookieService::LINK_RESULT_COOKIE, $token);

        $this->post('/auth/keycloak/link/confirm', ['confirmation' => 'link_keycloak_identity']);

        $this->assertResponseCode(303);
        $this->assertRedirect('/auth/keycloak/link/result');
        $this->assertCookieExpired(OidcCookieService::LINK_RESULT_COOKIE);
        $this->assertSame('no-store', $this->_response->getHeaderLine('Cache-Control'));
        $this->assertSame('no-cache', $this->_response->getHeaderLine('Pragma'));
        $this->assertResponseNotContains('MissingTemplateException');
        $identity = $this->identities()->find()->where(['user_id' => $user->id])->firstOrFail();
        $this->assertSame('immutable-subject', $identity->get('subject'));
        $transaction = $this->transactions()->get($transactionId);
        $this->assertSame(KeycloakSsoTransaction::STATUS_RESULT_CONSUMED, $transaction->get('status'));
        $this->assertNull($transaction->get('result_token_hash'));
        $this->assertNull($transaction->get('result_expires'));
        $this->assertNull($transaction->get('link_identity_ciphertext'));

        $this->cookie(OidcCookieService::LINK_RESULT_COOKIE, $token);
        $this->post('/auth/keycloak/link/confirm', ['confirmation' => 'link_keycloak_identity']);
        $this->assertResponseCode(303);
        $this->assertRedirect('/auth/keycloak/link/error');
        $this->assertSame(1, $this->identities()->find()->count());
    }

    public function testTerminalPostClaimFailureUsesGenericPrgAndCannotBeReplayed(): void
    {
        $user = $this->activeUser('collision@example.com');
        [$token, $transactionId] = $this->prepareResult($user, 'new-subject', $user->username);
        (new IdentityLinkPersistenceService())->create($user->id, new PendingIdentityLink(
            $this->configuration()->issuer,
            'already-linked-subject',
            $user->username
        ));
        $this->logInAs($user);
        $this->cookie(OidcCookieService::LINK_RESULT_COOKIE, $token);

        $this->post('/auth/keycloak/link/confirm', ['confirmation' => 'link_keycloak_identity']);

        $this->assertResponseCode(303);
        $this->assertRedirect('/auth/keycloak/link/error');
        $this->assertCookieExpired(OidcCookieService::LINK_RESULT_COOKIE);
        $transaction = $this->transactions()->get($transactionId);
        $this->assertSame(KeycloakSsoTransaction::STATUS_FAILED, $transaction->get('status'));
        $this->assertNull($transaction->get('result_token_hash'));
        $this->assertNull($transaction->get('result_expires'));
        $this->assertNull($transaction->get('link_identity_ciphertext'));

        $this->cookie(OidcCookieService::LINK_RESULT_COOKIE, $token);
        $this->post('/auth/keycloak/link/confirm', ['confirmation' => 'link_keycloak_identity']);
        $this->assertResponseCode(303);
        $this->assertRedirect('/auth/keycloak/link/error');
        $this->assertSame(1, $this->identities()->find()->count());
    }

    public function testResultPagesAreAuthenticatedNoStoreHtmlAndDoNotTouchProof(): void
    {
        $user = $this->activeUser('pending@example.com');
        [$token, $transactionId] = $this->prepareResult($user, 'private-subject', $user->username);
        $before = $this->transactions()->get($transactionId);
        $this->logInAs($user);

        $this->get('/auth/keycloak/link/result');

        $this->assertResponseOk();
        $this->assertStringStartsWith('text/html', $this->_response->getHeaderLine('Content-Type'));
        $this->assertSame('no-store', $this->_response->getHeaderLine('Cache-Control'));
        $this->assertSame('no-cache', $this->_response->getHeaderLine('Pragma'));
        $this->assertResponseContains('Keycloak identity linked');
        $this->assertSensitiveValuesAreAbsent($token, $user, 'private-subject');
        $this->assertProofUnchanged($before, $transactionId);

        $this->get('/auth/keycloak/link/error');

        $this->assertResponseOk();
        $this->assertStringStartsWith('text/html', $this->_response->getHeaderLine('Content-Type'));
        $this->assertSame('no-store', $this->_response->getHeaderLine('Cache-Control'));
        $this->assertSame('no-cache', $this->_response->getHeaderLine('Pragma'));
        $this->assertResponseContains('Keycloak identity link failed');
        $this->assertResponseContains('Please start the linking process again.');
        $this->assertSensitiveValuesAreAbsent($token, $user, 'private-subject');
        $this->assertProofUnchanged($before, $transactionId);
    }

    public function testResultPagesRequireAuthenticatedPassboltSession(): void
    {
        $this->get('/auth/keycloak/link/result');
        $this->assertResponseCode(302);

        $this->get('/auth/keycloak/link/error');
        $this->assertResponseCode(302);
    }

    public function testJsonUnlinkReturnsCleanupIdsAndDeletesServerState(): void
    {
        $user = $this->activeUser('unlink@example.com');
        $identity = (new IdentityLinkPersistenceService())->create($user->id, new PendingIdentityLink(
            $this->configuration()->issuer,
            'unlink-subject',
            $user->username
        ));
        $clientEnrollmentId = $this->createEnrollment($user, $identity->id);
        $this->logInAs($user);

        $this->postJson('/auth/keycloak/unlink.json', ['confirmation' => 'unlink_keycloak_identity']);

        $this->assertSuccess();
        $this->assertSame([$clientEnrollmentId], (array)$this->_responseJsonBody->client_enrollment_uuids);
        $this->assertSame(0, $this->identities()->find()->count());
        $this->assertSame(0, $this->enrollments()->find()->count());
    }

    public function testJsonUnlinkFailureIsGeneric(): void
    {
        $user = $this->activeUser('not-linked@example.com');
        $this->logInAs($user);

        $this->postJson('/auth/keycloak/unlink.json', ['confirmation' => 'unlink_keycloak_identity']);

        $this->assertResponseCode(400);
        $this->assertSame('error', $this->_responseJsonHeader->status);
        $this->assertSame('The Keycloak identity could not be unlinked.', $this->_responseJsonHeader->message);
        $this->assertResponseNotContains('identity_not_linked');
    }

    public function testNonJsonUnlinkIsRejectedBeforeMutation(): void
    {
        $user = $this->activeUser('html-unlink@example.com');
        (new IdentityLinkPersistenceService())->create($user->id, new PendingIdentityLink(
            $this->configuration()->issuer,
            'html-unlink-subject',
            $user->username
        ));
        $this->logInAs($user);

        $this->post('/auth/keycloak/unlink', ['confirmation' => 'unlink_keycloak_identity']);

        $this->assertResponseCode(404);
        $this->assertSame(1, $this->identities()->find()->count());
    }

    /** @return array{0: string, 1: string} */
    private function prepareResult(User $user, string $subject, string $email): array
    {
        $configuration = $this->configuration();
        $protector = new TransactionSecretProtector($configuration->transactionEncryptionKey);
        $created = (new CreateOidcTransactionService($protector))->create(
            $configuration->issuer,
            $configuration->clientId,
            $configuration->redirectUri,
            $configuration->configurationHash(),
            OidcConfigurationDto::TRANSACTION_TTL_SECONDS,
            KeycloakSsoTransaction::PURPOSE_IDENTITY_LINK,
            $user->id
        );
        $transactions = new ClaimOidcTransactionService($protector);
        $claimed = $transactions->claim(
            $created->state,
            $created->browserBinding,
            $configuration->configurationHash()
        );
        (new PrepareIdentityLinkService(
            new ExistingUserDiscoveryService(),
            new IdentityLinkPersistenceService(),
            new IdentityLinkProofProtector($protector)
        ))->prepare($claimed['transaction'], new ValidatedOidcIdentity($subject, $email));
        $token = $transactions->succeed(
            $claimed['transaction']->id,
            OidcConfigurationDto::IDENTITY_LINK_RESULT_TTL_SECONDS
        );

        return [$token, $claimed['transaction']->id];
    }

    private function createEnrollment(User $user, string $identityId): string
    {
        $clientEnrollmentId = UuidFactory::uuid();
        $enrollment = $this->enrollments()->newEmptyEntity();
        foreach (
            [
            'id' => UuidFactory::uuid(),
            'user_id' => $user->id,
            'identity_id' => $identityId,
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
            ] as $field => $value
        ) {
            $enrollment->set($field, $value);
        }
        $this->enrollments()->saveOrFail($enrollment);

        return $clientEnrollmentId;
    }

    private function assertSensitiveValuesAreAbsent(string $token, User $user, string $subject): void
    {
        $this->assertResponseNotContains($token);
        $this->assertResponseNotContains($user->id);
        $this->assertResponseNotContains($user->username);
        $this->assertResponseNotContains($subject);
        $this->assertResponseNotContains($this->configuration()->issuer);
    }

    private function assertProofUnchanged(KeycloakSsoTransaction $before, string $transactionId): void
    {
        $after = $this->transactions()->get($transactionId);
        $this->assertSame($before->get('status'), $after->get('status'));
        $this->assertSame($before->get('result_token_hash'), $after->get('result_token_hash'));
        $this->assertEquals($before->get('result_expires'), $after->get('result_expires'));
        $this->assertSame($before->get('link_identity_ciphertext'), $after->get('link_identity_ciphertext'));
    }

    private function activeUser(string $email): User
    {
        $user = UserFactory::make(['username' => $email])->user()->active()->notDisabled()->persist();
        self::assertInstanceOf(User::class, $user);

        return $user;
    }

    private function configuration(): OidcConfigurationDto
    {
        return (new OidcConfigurationService())->load();
    }

    private function identities(): Table
    {
        return TableRegistry::getTableLocator()->get('Passbolt/KeycloakSso.KeycloakSsoIdentities');
    }

    private function transactions(): Table
    {
        return TableRegistry::getTableLocator()->get('Passbolt/KeycloakSso.KeycloakSsoTransactions');
    }

    private function enrollments(): Table
    {
        return TableRegistry::getTableLocator()->get('Passbolt/KeycloakSso.KeycloakSsoCryptoEnrollments');
    }

    /** @return array<string, string> */
    private function environment(): array
    {
        return [
            KeycloakSsoEnvironment::ISSUER => 'https://keyclock.gobaz.ir/realms/passbolt',
            KeycloakSsoEnvironment::CLIENT_ID => 'passbolt',
            KeycloakSsoEnvironment::CLIENT_SECRET => 'client-secret-for-tests',
            KeycloakSsoEnvironment::REDIRECT_URI => 'https://passbolt.gobaz.ir/auth/keycloak/callback',
            KeycloakSsoEnvironment::TRANSACTION_ENCRYPTION_KEY => base64_encode(str_repeat('K', 32)),
        ];
    }
}
