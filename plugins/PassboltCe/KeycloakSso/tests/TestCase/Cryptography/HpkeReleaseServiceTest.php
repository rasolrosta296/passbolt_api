<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Cryptography;

use ParagonIE\HPKE\Factory;
use Passbolt\KeycloakSso\Cryptography\HpkeReleaseService;
use Passbolt\KeycloakSso\Error\Exception\CryptoSsoException;
use PHPUnit\Framework\TestCase;
use Throwable;

final class HpkeReleaseServiceTest extends TestCase
{
    public function testExactSuiteRoundTripAndTamperFailure(): void
    {
        $suite = Factory::dhkem_p256sha256_hkdf_sha256_aes128gcm();
        [$privateKey, $publicKey] = $suite->kem->generateKeys();
        $share = random_bytes(32);
        $aad = 'fixed release transcript';
        $info = 'fixed context binding';
        $package = (new HpkeReleaseService())->seal($share, base64_encode($publicKey->bytes), $aad, $info);
        $sealed = base64_decode($package['enc'], true) . base64_decode($package['ciphertext'], true);
        $this->assertSame($share, $suite->openBase($privateKey, $sealed, $aad, $info));

        $ciphertext = base64_decode($package['ciphertext'], true);
        $this->assertIsString($ciphertext);
        $ciphertext[0] = chr(ord($ciphertext[0]) ^ 1);
        $this->expectException(Throwable::class);
        $suite->openBase($privateKey, base64_decode($package['enc'], true) . $ciphertext, $aad, $info);
    }

    public function testRejectsWrongRecipientLength(): void
    {
        $this->expectException(CryptoSsoException::class);
        (new HpkeReleaseService())->seal(random_bytes(32), base64_encode(random_bytes(64)), 'aad', 'info');
    }
}
