<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Cryptography;

use ParagonIE\HPKE\Factory;
use ParagonIE\HPKE\KEM\DHKEM\Curve;
use ParagonIE\HPKE\KEM\DHKEM\EncapsKey;
use Passbolt\KeycloakSso\Error\Exception\CryptoSsoException;
use SensitiveParameter;
use Throwable;

final class HpkeReleaseService
{
    /** @return array{enc: string, ciphertext: string} */
    public function seal(
        #[SensitiveParameter]
        string $serverShare,
        string $encodedRecipientPublicKey,
        string $associatedData,
        string $info
    ): array {
        $recipient = base64_decode($encodedRecipientPublicKey, true);
        if (
            strlen($serverShare) !== 32 || $recipient === false || strlen($recipient) !== 65 ||
            !hash_equals(base64_encode($recipient), $encodedRecipientPublicKey) ||
            $associatedData === '' || $info === ''
        ) {
            throw new CryptoSsoException('hpke_release_input_invalid');
        }
        try {
            $hpke = Factory::dhkem_p256sha256_hkdf_sha256_aes128gcm();
            $sealed = $hpke->sealBase(
                new EncapsKey(Curve::NistP256, $recipient),
                $serverShare,
                $associatedData,
                $info
            );
            $encLength = $hpke->kem->getHeaderLength();
        } catch (Throwable) {
            throw new CryptoSsoException('hpke_release_failed');
        }

        return [
            'enc' => base64_encode(substr($sealed, 0, $encLength)),
            'ciphertext' => base64_encode(substr($sealed, $encLength)),
        ];
    }
}
