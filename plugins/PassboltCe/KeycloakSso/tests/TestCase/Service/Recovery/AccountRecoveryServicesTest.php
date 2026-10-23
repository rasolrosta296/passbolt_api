<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Service\Recovery;

use App\Model\Entity\AuthenticationToken;
use App\Model\Entity\User;
use App\Test\Factory\AuthenticationTokenFactory;
use App\Test\Factory\UserFactory;
use Cake\I18n\DateTime;
use Cake\ORM\Table;
use Cake\ORM\TableRegistry;
use Passbolt\KeycloakSso\Error\Exception\OidcTransactionException;
use Passbolt\KeycloakSso\Error\Exception\OidcValidationException;
use Passbolt\KeycloakSso\Model\Dto\AccountRecoveryConfigurationDto;
use Passbolt\KeycloakSso\Model\Dto\CreatedOidcTransaction;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;
use Passbolt\KeycloakSso\Model\Dto\PendingIdentityLink;
use Passbolt\KeycloakSso\Model\Dto\ValidatedOidcIdentity;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction;
use Passbolt\KeycloakSso\Service\Audit\IdentityLinkAuditService;
use Passbolt\KeycloakSso\Service\Identity\IdentityLinkPersistenceService;
use Passbolt\KeycloakSso\Service\Identity\UnlinkIdentityService;
use Passbolt\KeycloakSso\Service\Recovery\AccountRecoveryIdentityProofProtector;
use Passbolt\KeycloakSso\Service\Recovery\AccountRecoveryOidcProofService;
use Passbolt\KeycloakSso\Service\Recovery\AccountRecoveryResultService;
use Passbolt\KeycloakSso\Service\Transaction\ClaimOidcTransactionService;
use Passbolt\KeycloakSso\Service\Transaction\CreateOidcTransactionService;
use Passbolt\KeycloakSso\Service\Transaction\TransactionSecretProtector;
use Passbolt\KeycloakSso\Test\Lib\KeycloakSsoIntegrationTestCase;

final class AccountRecoveryServicesTest extends KeycloakSsoIntegrationTestCase
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

    public function testFreshLinkedProofMintsOneNormalRecoveryTokenOnlyWhenConsumed(): void
    {
        [$user, $claimed, $claims] = $this->linkedClaim();
        $before = AuthenticationTokenFactory::count();

        $this->proofs()->verify(
            $claimed,
            new ValidatedOidcIdentity(
                'immutable-subject',
                'changed-email-is-not-authoritative@example.com',
                time(),
                'urn:keycloak:acr:mfa',
                ['otp']
            )
        );
        $this->assertSame($before, AuthenticationTokenFactory::count());
        $result = $claims->succeed($claimed->id, OidcConfigurationDto::ACCOUNT_RECOVERY_RESULT_TTL_SECONDS);

        $grant = $this->results()->consume($result);

        $this->assertSame($user->id, $grant->userId);
        $this->assertMatchesRegularExpression('/^[a-f0-9-]{36}$/', $grant->token);
        $this->assertSame(1, AuthenticationTokenFactory::find()->where([
            'user_id' => $user->id,
            'type' => AuthenticationToken::TYPE_RECOVER,
            'active' => true,
        ])->count());
        $transaction = $this->transactions()->get($claimed->id);
        $this->assertInstanceOf(KeycloakSsoTransaction::class, $transaction);
        $this->assertSame(KeycloakSsoTransaction::STATUS_RESULT_CONSUMED, $transaction->status);
        $this->assertNull($transaction->result_token_hash);
        $this->assertNull($transaction->result_expires);
        $this->assertNull($transaction->link_identity_ciphertext);

        $this->expectException(OidcTransactionException::class);
        $this->results()->consume($result);
    }

    public function testRejectsUnlinkedIdentity(): void
    {
        $created = $this->createTransaction();
        $claimed = (new ClaimOidcTransactionService($this->protector))->claim(
            $created->state,
            $created->browserBinding,
            $this->oidc->configurationHash()
        )['transaction'];

        $this->expectException(OidcValidationException::class);
        $this->proofs()->verify(
            $claimed,
            new ValidatedOidcIdentity('unlinked-subject', 'irrelevant@example.com', time(), 'urn:keycloak:acr:mfa')
        );
    }

    public function testRejectsWrongAcrAndMissingAmr(): void
    {
        [, $claimed] = $this->linkedClaim();

        try {
            $this->proofs()->verify(
                $claimed,
                new ValidatedOidcIdentity('immutable-subject', 'irrelevant@example.com', time(), 'wrong', ['otp'])
            );
            $this->fail('Wrong ACR must fail.');
        } catch (OidcValidationException $exception) {
            $this->assertSame('oidc_acr_mismatch', $exception->reasonCode());
        }

        [, $secondClaimed] = $this->linkedClaim('second@example.com', 'second-subject');
        $this->expectException(OidcValidationException::class);
        $this->proofs()->verify(
            $secondClaimed,
            new ValidatedOidcIdentity('second-subject', 'irrelevant@example.com', time(), 'urn:keycloak:acr:mfa')
        );
    }

    public function testRejectsStaleAuthenticationTime(): void
    {
        [, $claimed] = $this->linkedClaim();

        try {
            $this->proofs()->verify(
                $claimed,
                new ValidatedOidcIdentity(
                    'immutable-subject',
                    'irrelevant@example.com',
                    $claimed->created->getTimestamp() - OidcConfigurationDto::CLOCK_SKEW_SECONDS - 1,
                    'urn:keycloak:acr:mfa',
                    ['otp']
                )
            );
            $this->fail('A stale authentication time must fail.');
        } catch (OidcValidationException $exception) {
            $this->assertSame('oidc_auth_time_not_fresh', $exception->reasonCode());
        }
    }

    public function testUserDisabledAfterOidcProofCannotReceiveRecoveryToken(): void
    {
        [$user, $claimed, $claims] = $this->linkedClaim();
        $this->proofs()->verify(
            $claimed,
            new ValidatedOidcIdentity(
                'immutable-subject',
                'irrelevant@example.com',
                time(),
                'urn:keycloak:acr:mfa',
                ['otp']
            )
        );
        $result = $claims->succeed($claimed->id, OidcConfigurationDto::ACCOUNT_RECOVERY_RESULT_TTL_SECONDS);
        $this->fetchTable('Users')->updateAll(['disabled' => DateTime::now()], ['id' => $user->id]);
        $before = AuthenticationTokenFactory::count();

        try {
            $this->results()->consume($result);
            $this->fail('A disabled user must not receive a recovery token.');
        } catch (OidcTransactionException) {
            $this->assertSame($before, AuthenticationTokenFactory::count());
        }
    }

    public function testConfigurationChangeInvalidatesUnconsumedRecoveryProof(): void
    {
        [, $claimed, $claims] = $this->linkedClaim();
        $this->proofs()->verify(
            $claimed,
            new ValidatedOidcIdentity(
                'immutable-subject',
                'irrelevant@example.com',
                time(),
                'urn:keycloak:acr:mfa',
                ['otp']
            )
        );
        $result = $claims->succeed($claimed->id, OidcConfigurationDto::ACCOUNT_RECOVERY_RESULT_TTL_SECONDS);
        $before = AuthenticationTokenFactory::count();

        try {
            (new AccountRecoveryResultService(
                $this->oidc->issuer,
                str_repeat('f', 64),
                $this->identityProofs()
            ))->consume($result);
            $this->fail('A configuration change must invalidate the proof.');
        } catch (OidcTransactionException) {
            $this->assertSame($before, AuthenticationTokenFactory::count());
        }
    }

    public function testIdentityRemovedAfterOidcProofCannotMintRecoveryToken(): void
    {
        [$user, $claimed, $claims] = $this->linkedClaim();
        $this->proofs()->verify(
            $claimed,
            new ValidatedOidcIdentity(
                'immutable-subject',
                'irrelevant@example.com',
                time(),
                'urn:keycloak:acr:mfa',
                ['otp']
            )
        );
        $result = $claims->succeed($claimed->id, OidcConfigurationDto::ACCOUNT_RECOVERY_RESULT_TTL_SECONDS);
        $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoIdentities')->deleteAll(['user_id' => $user->id]);
        $before = AuthenticationTokenFactory::count();

        try {
            $this->results()->consume($result);
            $this->fail('An unlinked identity must not mint a recovery token.');
        } catch (OidcTransactionException) {
            $this->assertSame($before, AuthenticationTokenFactory::count());
        }
    }

    public function testTamperedIdentityBindingCannotMintRecoveryToken(): void
    {
        [, $claimed, $claims] = $this->linkedClaim();
        $this->proofs()->verify(
            $claimed,
            new ValidatedOidcIdentity(
                'immutable-subject',
                'irrelevant@example.com',
                time(),
                'urn:keycloak:acr:mfa',
                ['otp']
            )
        );
        $ciphertext = (string)$claimed->link_identity_ciphertext;
        $tampered = substr($ciphertext, 0, -1) . (str_ends_with($ciphertext, 'A') ? 'B' : 'A');
        $this->transactions()->updateAll(['link_identity_ciphertext' => $tampered], ['id' => $claimed->id]);
        $result = $claims->succeed($claimed->id, OidcConfigurationDto::ACCOUNT_RECOVERY_RESULT_TTL_SECONDS);
        $before = AuthenticationTokenFactory::count();

        try {
            $this->results()->consume($result);
            $this->fail('A tampered identity binding must not mint a recovery token.');
        } catch (OidcTransactionException) {
            $this->assertSame($before, AuthenticationTokenFactory::count());
        }
    }

    public function testUnlinkRevokesOutstandingRecoveryResult(): void
    {
        [$user, $claimed, $claims] = $this->linkedClaim();
        $this->proofs()->verify(
            $claimed,
            new ValidatedOidcIdentity(
                'immutable-subject',
                'irrelevant@example.com',
                time(),
                'urn:keycloak:acr:mfa',
                ['otp']
            )
        );
        $result = $claims->succeed($claimed->id, OidcConfigurationDto::ACCOUNT_RECOVERY_RESULT_TTL_SECONDS);

        (new UnlinkIdentityService($this->oidc->issuer, new IdentityLinkAuditService()))->unlink($user->id);

        $transaction = $this->transactions()->get($claimed->id);
        $this->assertInstanceOf(KeycloakSsoTransaction::class, $transaction);
        $this->assertSame(KeycloakSsoTransaction::STATUS_FAILED, $transaction->status);
        $this->assertSame('identity_unlinked', $transaction->failure_code);
        $this->assertNull($transaction->result_token_hash);
        $this->assertNull($transaction->link_identity_ciphertext);
        $this->expectException(OidcTransactionException::class);
        $this->results()->consume($result);
    }

    public function testExpiredRecoveryProofCannotMintRecoveryToken(): void
    {
        [, $claimed, $claims] = $this->linkedClaim();
        $this->proofs()->verify(
            $claimed,
            new ValidatedOidcIdentity(
                'immutable-subject',
                'irrelevant@example.com',
                time(),
                'urn:keycloak:acr:mfa',
                ['otp']
            )
        );
        $result = $claims->succeed($claimed->id, OidcConfigurationDto::ACCOUNT_RECOVERY_RESULT_TTL_SECONDS);
        $this->transactions()->updateAll(
            ['result_expires' => DateTime::now()->subMinutes(1)],
            ['id' => $claimed->id]
        );
        $before = AuthenticationTokenFactory::count();

        try {
            $this->results()->consume($result);
            $this->fail('An expired proof must not mint a recovery token.');
        } catch (OidcTransactionException) {
            $this->assertSame($before, AuthenticationTokenFactory::count());
        }
    }

    /** @return array{0: User, 1: KeycloakSsoTransaction, 2: ClaimOidcTransactionService} */
    private function linkedClaim(
        string $email = 'user@example.com',
        string $subject = 'immutable-subject'
    ): array {
        $user = UserFactory::make(['username' => $email])->user()->active()->notDisabled()->persist();
        $this->assertInstanceOf(User::class, $user);
        (new IdentityLinkPersistenceService())->create(
            $user->id,
            new PendingIdentityLink($this->oidc->issuer, $subject, $email)
        );
        $created = $this->createTransaction();
        $claims = new ClaimOidcTransactionService($this->protector);
        $claimed = $claims->claim(
            $created->state,
            $created->browserBinding,
            $this->oidc->configurationHash()
        )['transaction'];

        return [$user, $claimed, $claims];
    }

    private function createTransaction(): CreatedOidcTransaction
    {
        return (new CreateOidcTransactionService($this->protector))->create(
            $this->oidc->issuer,
            $this->oidc->clientId,
            $this->oidc->redirectUri,
            $this->oidc->configurationHash(),
            OidcConfigurationDto::TRANSACTION_TTL_SECONDS,
            KeycloakSsoTransaction::PURPOSE_ACCOUNT_RECOVERY
        );
    }

    private function proofs(): AccountRecoveryOidcProofService
    {
        return new AccountRecoveryOidcProofService(
            $this->identityProofs(),
            new AccountRecoveryConfigurationDto('urn:keycloak:acr:mfa', ['otp'])
        );
    }

    private function results(): AccountRecoveryResultService
    {
        return new AccountRecoveryResultService(
            $this->oidc->issuer,
            $this->oidc->configurationHash(),
            $this->identityProofs()
        );
    }

    private function identityProofs(): AccountRecoveryIdentityProofProtector
    {
        return new AccountRecoveryIdentityProofProtector($this->protector);
    }

    private function transactions(): Table
    {
        return TableRegistry::getTableLocator()->get('Passbolt/KeycloakSso.KeycloakSsoTransactions');
    }
}
