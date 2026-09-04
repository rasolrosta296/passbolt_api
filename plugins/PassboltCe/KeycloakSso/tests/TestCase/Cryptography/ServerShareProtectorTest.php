<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Cryptography;

use Passbolt\KeycloakSso\Cryptography\ServerShareProtector;
use Passbolt\KeycloakSso\Error\Exception\CryptoSsoException;
use Passbolt\KeycloakSso\Model\Dto\CryptoConfigurationDto;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ServerShareProtectorTest extends TestCase
{
    public function testRoundTripAndDecryptOnlyKeyRotation(): void
    {
        $oldKey = random_bytes(32);
        $old = new ServerShareProtector($this->configuration('old', ['old' => $oldKey]));
        $share = random_bytes(32);
        $aad = 'fixed context AAD';
        $protected = $old->encrypt($share, $aad);

        $rotated = new ServerShareProtector($this->configuration('new', [
            'old' => $oldKey,
            'new' => random_bytes(32),
        ]));
        $this->assertSame($share, $rotated->decrypt(
            $protected['ciphertext'],
            $protected['nonce'],
            $protected['keyId'],
            $aad
        ));
        $this->assertSame('new', $rotated->encrypt(random_bytes(32), $aad)['keyId']);
    }

    #[DataProvider('tamperProvider')]
    public function testFailsClosedOnTampering(string $field): void
    {
        $protector = new ServerShareProtector($this->configuration('active', ['active' => random_bytes(32)]));
        $protected = $protector->encrypt(random_bytes(32), 'expected aad');
        if ($field === 'aad') {
            $aad = 'wrong aad';
        } else {
            $aad = 'expected aad';
            $bytes = base64_decode($protected[$field], true);
            $this->assertIsString($bytes);
            $bytes[0] = chr(ord($bytes[0]) ^ 1);
            $protected[$field] = base64_encode($bytes);
        }
        $this->expectException(CryptoSsoException::class);
        $protector->decrypt($protected['ciphertext'], $protected['nonce'], $protected['keyId'], $aad);
    }

    public static function tamperProvider(): array
    {
        return [['ciphertext'], ['nonce'], ['aad']];
    }

    /** @param array<string, string> $keys */
    private function configuration(string $active, array $keys): CryptoConfigurationDto
    {
        return new CryptoConfigurationDto('https://passbolt.example.test', 'mfa', [], $active, $keys);
    }
}
