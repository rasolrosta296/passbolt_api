<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Transaction;

use Passbolt\KeycloakSso\Error\Exception\OidcTransactionException;

final class TransactionSecretProtector
{
    public function __construct(private readonly string $key)
    {
        if (strlen($key) !== SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES) {
            throw new OidcTransactionException('The transaction encryption key has an invalid length.');
        }
    }

    public function encrypt(string $plaintext, string $associatedData): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
            $plaintext,
            $associatedData,
            $nonce,
            $this->key
        );

        return base64_encode($nonce . $ciphertext);
    }

    public function decrypt(string $encodedCiphertext, string $associatedData): string
    {
        $payload = base64_decode($encodedCiphertext, true);
        if ($payload === false || strlen($payload) <= SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES) {
            throw new OidcTransactionException('The protected transaction secret is invalid.');
        }

        $nonceLength = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
        $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
            substr($payload, $nonceLength),
            $associatedData,
            substr($payload, 0, $nonceLength),
            $this->key
        );
        if ($plaintext === false) {
            throw new OidcTransactionException('The protected transaction secret cannot be authenticated.');
        }

        return $plaintext;
    }
}
