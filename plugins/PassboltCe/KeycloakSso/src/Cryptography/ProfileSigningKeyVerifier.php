<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Cryptography;

use JsonException;
use Mdanter\Ecc\Serializer\PublicKey\DerPublicKeySerializer;
use Mdanter\Ecc\Serializer\PublicKey\PemPublicKeySerializer;
use Mdanter\Ecc\Serializer\Signature\DerSignatureSerializer;
use Mdanter\Ecc\Serializer\Signature\IEEEP1363Serializer;
use ParagonIE\HPKE\KEM\DHKEM\Curve;
use ParagonIE\HPKE\KEM\DHKEM\EncapsKey;
use Passbolt\KeycloakSso\Error\Exception\CryptoSsoException;
use SensitiveParameter;
use Throwable;

final class ProfileSigningKeyVerifier
{
    /** @return array{canonical: string, thumbprint: string, raw: string} */
    public function validatePublicJwk(string $jwkJson): array
    {
        if ($jwkJson === '' || strlen($jwkJson) > 2048) {
            throw new CryptoSsoException('signing_public_key_invalid');
        }
        try {
            $jwk = json_decode($jwkJson, true, 8, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new CryptoSsoException('signing_public_key_invalid');
        }
        $keys = is_array($jwk) ? array_keys($jwk) : [];
        sort($keys);
        if ($keys !== ['crv', 'ext', 'key_ops', 'kty', 'x', 'y']) {
            throw new CryptoSsoException('signing_public_key_invalid');
        }
        if (
            !is_array($jwk) || ($jwk['kty'] ?? null) !== 'EC' || ($jwk['crv'] ?? null) !== 'P-256' ||
            ($jwk['ext'] ?? null) !== true || ($jwk['key_ops'] ?? null) !== ['verify'] ||
            !is_string($jwk['x'] ?? null) || !is_string($jwk['y'] ?? null) ||
            preg_match('/^[A-Za-z0-9_-]{43}$/D', $jwk['x']) !== 1 ||
            preg_match('/^[A-Za-z0-9_-]{43}$/D', $jwk['y']) !== 1
        ) {
            throw new CryptoSsoException('signing_public_key_invalid');
        }
        $canonicalThumbprintInput = json_encode([
            'crv' => 'P-256',
            'kty' => 'EC',
            'x' => $jwk['x'],
            'y' => $jwk['y'],
        ], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        $canonical = json_encode([
            'crv' => 'P-256',
            'ext' => true,
            'key_ops' => ['verify'],
            'kty' => 'EC',
            'x' => $jwk['x'],
            'y' => $jwk['y'],
        ], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        $x = self::base64UrlDecode($jwk['x']);
        $y = self::base64UrlDecode($jwk['y']);
        if (strlen($x) !== 32 || strlen($y) !== 32) {
            throw new CryptoSsoException('signing_public_key_invalid');
        }

        return [
            'canonical' => $canonical,
            'thumbprint' => self::base64Url(hash('sha256', $canonicalThumbprintInput, true)),
            'raw' => "\x04" . $x . $y,
        ];
    }

    /**
     * Verify an IEEE P1363 ECDSA P-256/SHA-256 signature.
     */
    public function verify(
        string $canonicalJwk,
        string $message,
        #[SensitiveParameter]
        string $encodedSignature
    ): void {
        $signature = base64_decode($encodedSignature, true);
        if (
            $signature === false || strlen($signature) !== 64 ||
            !hash_equals(base64_encode($signature), $encodedSignature)
        ) {
            throw new CryptoSsoException('profile_signature_invalid');
        }
        try {
            $raw = $this->validatePublicJwk($canonicalJwk)['raw'];
            $key = (new EncapsKey(Curve::NistP256, $raw))->toPublicKey();
            $signatureObject = (new IEEEP1363Serializer())->parse($signature);
            $derSignature = (new DerSignatureSerializer())->serialize($signatureObject);
            $pem = (new PemPublicKeySerializer(new DerPublicKeySerializer()))->serialize($key);
            $verified = openssl_verify($message, $derSignature, $pem, OPENSSL_ALGO_SHA256);
        } catch (Throwable) {
            $verified = false;
        }
        if ($verified !== 1) {
            throw new CryptoSsoException('profile_signature_invalid');
        }
    }

    /**
     * Strictly decode canonical unpadded base64url.
     */
    private static function base64UrlDecode(string $value): string
    {
        $decoded = base64_decode(strtr($value, '-_', '+/') . '=', true);
        if ($decoded === false || !hash_equals(self::base64Url($decoded), $value)) {
            throw new CryptoSsoException('signing_public_key_invalid');
        }

        return $decoded;
    }

    /**
     * Encode unpadded base64url.
     */
    private static function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
