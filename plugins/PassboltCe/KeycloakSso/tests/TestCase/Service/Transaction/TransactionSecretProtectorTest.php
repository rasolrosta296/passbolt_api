<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Service\Transaction;

use Cake\TestSuite\TestCase;
use Passbolt\KeycloakSso\Error\Exception\OidcTransactionException;
use Passbolt\KeycloakSso\Service\Transaction\TransactionSecretProtector;

final class TransactionSecretProtectorTest extends TestCase
{
    public function testRoundTripWithAssociatedData(): void
    {
        $protector = new TransactionSecretProtector(random_bytes(32));
        $ciphertext = $protector->encrypt('pkce-verifier', 'transaction:configuration');

        $this->assertNotSame('pkce-verifier', $ciphertext);
        $this->assertSame(
            'pkce-verifier',
            $protector->decrypt($ciphertext, 'transaction:configuration')
        );
    }

    public function testRejectsTamperedCiphertext(): void
    {
        $protector = new TransactionSecretProtector(random_bytes(32));
        $ciphertext = $protector->encrypt('pkce-verifier', 'transaction:configuration');
        $decoded = base64_decode($ciphertext, true);
        $decoded[30] = chr(ord($decoded[30]) ^ 1);

        $this->expectException(OidcTransactionException::class);
        $protector->decrypt(base64_encode($decoded), 'transaction:configuration');
    }

    public function testRejectsWrongAssociatedData(): void
    {
        $protector = new TransactionSecretProtector(random_bytes(32));
        $ciphertext = $protector->encrypt('pkce-verifier', 'transaction:configuration');

        $this->expectException(OidcTransactionException::class);
        $protector->decrypt($ciphertext, 'different-transaction');
    }

    public function testRejectsInvalidKeyLength(): void
    {
        $this->expectException(OidcTransactionException::class);
        new TransactionSecretProtector('too-short');
    }
}
