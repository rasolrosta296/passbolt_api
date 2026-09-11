<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Service\Crypto;

use App\Model\Entity\User;
use App\Test\Factory\UserFactory;
use App\Utility\UuidFactory;
use Cake\I18n\DateTime;
use Cake\ORM\TableRegistry;
use Passbolt\KeycloakSso\Error\Exception\CryptoSsoException;
use Passbolt\KeycloakSso\Error\Exception\OidcValidationException;
use Passbolt\KeycloakSso\Model\Dto\CryptoConfigurationDto;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;
use Passbolt\KeycloakSso\Model\Dto\PendingIdentityLink;
use Passbolt\KeycloakSso\Model\Dto\ValidatedOidcIdentity;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoCryptoRequest;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction;
use Passbolt\KeycloakSso\Service\Crypto\CryptoOidcProofService;
use Passbolt\KeycloakSso\Service\Crypto\CryptoResultClaimService;
use Passbolt\KeycloakSso\Service\Identity\IdentityLinkPersistenceService;
use Passbolt\KeycloakSso\Service\Transaction\ClaimOidcTransactionService;
use Passbolt\KeycloakSso\Service\Transaction\CreateOidcTransactionService;
use Passbolt\KeycloakSso\Service\Transaction\TransactionSecretProtector;
use Passbolt\KeycloakSso\Test\Lib\KeycloakSsoIntegrationTestCase;

final class CryptoOidcProofServiceTest extends KeycloakSsoIntegrationTestCase
{
    private OidcConfigurationDto $oidc;
    private TransactionSecretProtector $protector;

    public function setUp(): void
    {
        parent::setUp();
        $this->oidc = new OidcConfigurationDto(
            'https://keyclock.gobaz.ir/realms/passbolt',
            'passbolt',
            'client-secret-for-tests',
            'https://passbolt.gobaz.ir/auth/keycloak/callback',
            random_bytes(32)
        );
        $this->protector = new TransactionSecretProtector($this->oidc->transactionEncryptionKey);
    }

    public function testFreshExactLinkedIdentityCreatesOneTimeCapabilityOnly(): void
    {
        [$user, $transaction, $created] = $this->pendingRelease();
        $claims = new ClaimOidcTransactionService($this->protector);
        $claimed = $claims->claim($created->state, $created->browserBinding, $this->oidc->configurationHash());
        (new CryptoOidcProofService($this->crypto()))->verify(
            $claimed['transaction'],
            new ValidatedOidcIdentity('immutable-subject', $user->username, time(), 'urn:keycloak:acr:mfa')
        );
        $token = $claims->succeed($transaction->id, OidcConfigurationDto::CRYPTO_RESULT_TTL_SECONDS);
        $consumer = new CryptoResultClaimService();
        $first = $consumer->claim($token, KeycloakSsoCryptoRequest::PURPOSE_RELEASE);
        $this->assertSame(KeycloakSsoCryptoRequest::STATUS_PROCESSING, $first['request']->status);

        $this->expectException(CryptoSsoException::class);
        $consumer->claim($token, KeycloakSsoCryptoRequest::PURPOSE_RELEASE);
    }

    public function testRejectsStaleAuthTime(): void
    {
        [$user, $transaction] = $this->pendingRelease();
        $this->expectException(OidcValidationException::class);
        (new CryptoOidcProofService($this->crypto()))->verify(
            $transaction,
            new ValidatedOidcIdentity('immutable-subject', $user->username, time() - 120, 'urn:keycloak:acr:mfa')
        );
    }

    public function testRejectsWrongAcr(): void
    {
        [$user, $transaction] = $this->pendingRelease();
        $this->expectException(OidcValidationException::class);
        (new CryptoOidcProofService($this->crypto()))->verify(
            $transaction,
            new ValidatedOidcIdentity('immutable-subject', $user->username, time(), 'wrong-acr')
        );
    }

    public function testRejectsMissingAcr(): void
    {
        [$user, $transaction] = $this->pendingRelease();
        $this->expectException(OidcValidationException::class);
        (new CryptoOidcProofService($this->crypto()))->verify(
            $transaction,
            new ValidatedOidcIdentity('immutable-subject', $user->username, time())
        );
    }

    public function testRejectsMissingRequiredAmr(): void
    {
        [$user, $transaction] = $this->pendingRelease();
        $configuration = new CryptoConfigurationDto(
            'https://passbolt.gobaz.ir',
            'urn:keycloak:acr:mfa',
            ['otp'],
            'active',
            ['active' => random_bytes(32)]
        );
        $this->expectException(OidcValidationException::class);
        (new CryptoOidcProofService($configuration))->verify(
            $transaction,
            new ValidatedOidcIdentity('immutable-subject', $user->username, time(), 'urn:keycloak:acr:mfa', ['pwd'])
        );
    }

    public function testRejectsSubjectChange(): void
    {
        [$user, $transaction] = $this->pendingRelease();
        $this->expectException(OidcValidationException::class);
        (new CryptoOidcProofService($this->crypto()))->verify(
            $transaction,
            new ValidatedOidcIdentity('changed-subject', $user->username, time(), 'urn:keycloak:acr:mfa')
        );
    }

    public function testRejectsDisabledUserWithMatchingIdentity(): void
    {
        [$user, $transaction] = $this->pendingRelease();
        TableRegistry::getTableLocator()->get('Users')->updateAll(['disabled' => DateTime::now()], [
            'id' => $user->id,
        ]);
        try {
            (new CryptoOidcProofService($this->crypto()))->verify(
                $transaction,
                new ValidatedOidcIdentity('immutable-subject', $user->username, time(), 'urn:keycloak:acr:mfa')
            );
            $this->fail('A disabled Passbolt user must not complete a cryptographic OIDC proof.');
        } catch (OidcValidationException $exception) {
            $this->assertSame('crypto_user_unavailable', $exception->reasonCode());
        }
    }

    public function testRejectsDeletedUserWithMatchingIdentity(): void
    {
        [$user, $transaction] = $this->pendingRelease();
        TableRegistry::getTableLocator()->get('Users')->updateAll(['deleted' => true], ['id' => $user->id]);
        try {
            (new CryptoOidcProofService($this->crypto()))->verify(
                $transaction,
                new ValidatedOidcIdentity('immutable-subject', $user->username, time(), 'urn:keycloak:acr:mfa')
            );
            $this->fail('A deleted Passbolt user must not complete a cryptographic OIDC proof.');
        } catch (OidcValidationException $exception) {
            $this->assertSame('crypto_user_unavailable', $exception->reasonCode());
        }
    }

    /** @return array{0: User, 1: KeycloakSsoTransaction, 2: \Passbolt\KeycloakSso\Model\Dto\CreatedOidcTransaction} */
    private function pendingRelease(): array
    {
        $user = UserFactory::make(['username' => 'user@example.com'])->user()->active()->notDisabled()->persist();
        self::assertInstanceOf(User::class, $user);
        $identity = (new IdentityLinkPersistenceService())->create($user->id, new PendingIdentityLink(
            $this->oidc->issuer,
            'immutable-subject',
            $user->username
        ));
        $requestId = UuidFactory::uuid();
        $request = TableRegistry::getTableLocator()
            ->get('Passbolt/KeycloakSso.KeycloakSsoCryptoRequests')
            ->newEmptyEntity();
        foreach (
            [
            'id' => $requestId,
            'purpose' => KeycloakSsoCryptoRequest::PURPOSE_RELEASE,
            'user_id' => $user->id,
            'identity_id' => $identity->id,
            'enrollment_id' => UuidFactory::uuid(),
            'request_ciphertext' => 'protected-dummy-request',
            'client_nonce_hash' => hash('sha256', random_bytes(32)),
            'status' => KeycloakSsoCryptoRequest::STATUS_PENDING_OIDC,
            'expires' => DateTime::now()->addMinutes(5),
            ] as $field => $value
        ) {
            $request->set($field, $value);
        }
        TableRegistry::getTableLocator()
            ->get('Passbolt/KeycloakSso.KeycloakSsoCryptoRequests')
            ->saveOrFail($request);
        $created = (new CreateOidcTransactionService($this->protector))->create(
            $this->oidc->issuer,
            $this->oidc->clientId,
            $this->oidc->redirectUri,
            $this->oidc->configurationHash(),
            OidcConfigurationDto::TRANSACTION_TTL_SECONDS,
            KeycloakSsoTransaction::PURPOSE_CRYPTO_RELEASE,
            $user->id,
            $requestId
        );
        $transaction = TableRegistry::getTableLocator()
            ->get('Passbolt/KeycloakSso.KeycloakSsoTransactions')
            ->get($created->id);
        self::assertInstanceOf(KeycloakSsoTransaction::class, $transaction);

        return [$user, $transaction, $created];
    }

    private function crypto(): CryptoConfigurationDto
    {
        return new CryptoConfigurationDto(
            'https://passbolt.gobaz.ir',
            'urn:keycloak:acr:mfa',
            [],
            'active',
            ['active' => random_bytes(32)]
        );
    }
}
