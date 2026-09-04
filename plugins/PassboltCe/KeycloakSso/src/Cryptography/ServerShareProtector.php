<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Cryptography;

use Passbolt\KeycloakSso\Error\Exception\CryptoSsoException;
use Passbolt\KeycloakSso\Model\Dto\CryptoConfigurationDto;
use SensitiveParameter;
use SodiumException;

final class ServerShareProtector
{
    public const NONCE_BYTES = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;

    /**
     * Construct the deployment-KEK share protector.
     */
    public function __construct(private readonly CryptoConfigurationDto $configuration)
    {
    }

    /** @return array{ciphertext: string, nonce: string, keyId: string} Canonical base64 values. */
    public function encrypt(#[SensitiveParameter]
    string $serverShare, string $associatedData): array
    {
        if (strlen($serverShare) !== 32 || $associatedData === '') {
            throw new CryptoSsoException('server_share_input_invalid');
        }
        $nonce = random_bytes(self::NONCE_BYTES);
        $keyId = $this->configuration->activeServerShareKeyId;
        try {
            $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $serverShare,
                $associatedData,
                $nonce,
                $this->configuration->serverShareKeys[$keyId]
            );
        } catch (SodiumException) {
            throw new CryptoSsoException('server_share_encryption_failed');
        }

        return ['ciphertext' => base64_encode($ciphertext), 'nonce' => base64_encode($nonce), 'keyId' => $keyId];
    }

    /**
     * Authenticate and decrypt an exactly 32-byte server share.
     */
    public function decrypt(
        #[SensitiveParameter]
        string $encodedCiphertext,
        string $encodedNonce,
        string $keyId,
        string $associatedData
    ): string {
        $ciphertext = base64_decode($encodedCiphertext, true);
        $nonce = base64_decode($encodedNonce, true);
        $key = $this->configuration->serverShareKeys[$keyId] ?? null;
        if (
            $ciphertext === false || strlen($ciphertext) !== 48 ||
            $nonce === false || strlen($nonce) !== self::NONCE_BYTES ||
            !hash_equals(base64_encode($ciphertext), $encodedCiphertext) ||
            !hash_equals(base64_encode($nonce), $encodedNonce) ||
            !is_string($key) || $associatedData === ''
        ) {
            throw new CryptoSsoException('server_share_unavailable');
        }
        try {
            $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                $ciphertext,
                $associatedData,
                $nonce,
                $key
            );
        } catch (SodiumException) {
            $plaintext = false;
        }
        if (!is_string($plaintext) || strlen($plaintext) !== 32) {
            throw new CryptoSsoException('server_share_authentication_failed');
        }

        return $plaintext;
    }
}
