<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Service\Transaction;

use Cake\I18n\DateTime;
use Cake\ORM\TableRegistry;
use Passbolt\KeycloakSso\Error\Exception\OidcTransactionException;
use Passbolt\KeycloakSso\Model\Dto\CreatedOidcTransaction;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction;
use Passbolt\KeycloakSso\Service\Transaction\ClaimOidcTransactionService;
use Passbolt\KeycloakSso\Service\Transaction\CleanupOidcTransactionsService;
use Passbolt\KeycloakSso\Service\Transaction\CreateOidcTransactionService;
use Passbolt\KeycloakSso\Service\Transaction\TransactionSecretProtector;
use Passbolt\KeycloakSso\Test\Lib\KeycloakSsoIntegrationTestCase;

final class OidcTransactionReplayTest extends KeycloakSsoIntegrationTestCase
{
    private TransactionSecretProtector $protector;

    public function setUp(): void
    {
        parent::setUp();
        $this->protector = new TransactionSecretProtector(random_bytes(32));
    }

    public function testStoresOnlyHashesAndAuthenticatedEncryptedVerifier(): void
    {
        $created = $this->create();
        $transaction = TableRegistry::getTableLocator()
            ->get('Passbolt/KeycloakSso.KeycloakSsoTransactions')
            ->get($created->id);
        assert($transaction instanceof KeycloakSsoTransaction);

        $this->assertSame(hash('sha256', $created->state), $transaction->state_hash);
        $this->assertSame(hash('sha256', $created->nonce), $transaction->nonce_hash);
        $this->assertSame(hash('sha256', $created->browserBinding), $transaction->browser_binding_hash);
        $this->assertStringNotContainsString($created->pkceVerifier, $transaction->pkce_verifier_ciphertext);
        $this->assertStringNotContainsString($created->state, json_encode($transaction, JSON_THROW_ON_ERROR));
        $this->assertStringNotContainsString($created->nonce, json_encode($transaction, JSON_THROW_ON_ERROR));
    }

    public function testOnlyOneCallbackCanAtomicallyClaimTransaction(): void
    {
        $created = $this->create();
        $service = new ClaimOidcTransactionService($this->protector);

        $claimed = $service->claim($created->state, $created->browserBinding, str_repeat('c', 64));
        $this->assertSame($created->pkceVerifier, $claimed['pkceVerifier']);

        $this->expectException(OidcTransactionException::class);
        $service->claim($created->state, $created->browserBinding, str_repeat('c', 64));
    }

    public function testStateMismatchCannotClaimTransaction(): void
    {
        $created = $this->create();
        $service = new ClaimOidcTransactionService($this->protector);

        $this->expectException(OidcTransactionException::class);
        $service->claim(str_repeat('x', 43), $created->browserBinding, str_repeat('c', 64));
    }

    public function testBrowserBindingMismatchTerminallyConsumesTransaction(): void
    {
        $created = $this->create();
        $service = new ClaimOidcTransactionService($this->protector);

        try {
            $service->claim($created->state, str_repeat('x', 43), str_repeat('c', 64));
            $this->fail('Expected browser binding rejection.');
        } catch (OidcTransactionException) {
            $transaction = TableRegistry::getTableLocator()
                ->get('Passbolt/KeycloakSso.KeycloakSsoTransactions')
                ->get($created->id);
            assert($transaction instanceof KeycloakSsoTransaction);
            $this->assertSame(KeycloakSsoTransaction::STATUS_FAILED, $transaction->status);
            $this->assertNull($transaction->pkce_verifier_ciphertext);
        }
    }

    public function testExpiredTransactionCannotBeClaimedAndVerifierIsErased(): void
    {
        $created = $this->create();
        $table = TableRegistry::getTableLocator()->get('Passbolt/KeycloakSso.KeycloakSsoTransactions');
        $table->updateAll(['expires' => DateTime::yesterday()], ['id' => $created->id]);

        try {
            (new ClaimOidcTransactionService($this->protector))->claim(
                $created->state,
                $created->browserBinding,
                str_repeat('c', 64)
            );
            $this->fail('Expected expiry rejection.');
        } catch (OidcTransactionException) {
            $transaction = $table->get($created->id);
            assert($transaction instanceof KeycloakSsoTransaction);
            $this->assertSame(KeycloakSsoTransaction::STATUS_FAILED, $transaction->status);
            $this->assertNull($transaction->pkce_verifier_ciphertext);
        }
    }

    public function testCleanupErasesAbandonedExpiredVerifier(): void
    {
        $created = $this->create();
        $table = TableRegistry::getTableLocator()->get('Passbolt/KeycloakSso.KeycloakSsoTransactions');
        $table->updateAll(['expires' => DateTime::yesterday()], ['id' => $created->id]);

        $result = (new CleanupOidcTransactionsService())->run();
        $transaction = $table->get($created->id);
        assert($transaction instanceof KeycloakSsoTransaction);

        $this->assertSame(1, $result['expired']);
        $this->assertSame(KeycloakSsoTransaction::STATUS_FAILED, $transaction->status);
        $this->assertNull($transaction->pkce_verifier_ciphertext);
    }

    private function create(): CreatedOidcTransaction
    {
        return (new CreateOidcTransactionService($this->protector))->create(
            'https://keyclock.gobaz.ir/realms/passbolt',
            'passbolt',
            'https://passbolt.gobaz.ir/auth/keycloak/callback',
            str_repeat('c', 64),
            300
        );
    }
}
