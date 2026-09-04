<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Cryptography;

use Mdanter\Ecc\Serializer\Signature\DerSignatureSerializer;
use Mdanter\Ecc\Serializer\Signature\IEEEP1363Serializer;
use Passbolt\KeycloakSso\Cryptography\ProfileSigningKeyVerifier;
use Passbolt\KeycloakSso\Error\Exception\CryptoSsoException;
use PHPUnit\Framework\TestCase;

final class ProfileSigningKeyVerifierTest extends TestCase
{
    public function testVerifiesWebCryptoP1363SignatureEncoding(): void
    {
        [$privateKey, $jwk] = $this->keyPair();
        $message = 'fixed deterministic transcript';
        openssl_sign($message, $derSignature, $privateKey, OPENSSL_ALGO_SHA256);
        $signature = (new IEEEP1363Serializer())->serialize(
            (new DerSignatureSerializer())->parse($derSignature),
            256
        );
        $verifier = new ProfileSigningKeyVerifier();
        $validated = $verifier->validatePublicJwk($jwk);
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/D', $validated['thumbprint']);
        $verifier->verify($validated['canonical'], $message, base64_encode($signature));
        $this->assertTrue(true);
    }

    public function testRejectsModifiedMessageAndMalformedSignature(): void
    {
        [$privateKey, $jwk] = $this->keyPair();
        openssl_sign('message', $derSignature, $privateKey, OPENSSL_ALGO_SHA256);
        $signature = (new IEEEP1363Serializer())->serialize(
            (new DerSignatureSerializer())->parse($derSignature),
            256
        );
        $verifier = new ProfileSigningKeyVerifier();
        $canonical = $verifier->validatePublicJwk($jwk)['canonical'];

        try {
            $verifier->verify($canonical, 'modified', base64_encode($signature));
            $this->fail('A signature for a different transcript was accepted.');
        } catch (CryptoSsoException $exception) {
            $this->assertSame('profile_signature_invalid', $exception->reasonCode());
        }
        $this->expectException(CryptoSsoException::class);
        $verifier->verify($canonical, 'message', base64_encode(random_bytes(63)));
    }

    public function testRejectsAlgorithmConfusionAndUnknownJwkFields(): void
    {
        [, $jwk] = $this->keyPair();
        $decoded = json_decode($jwk, true, 8, JSON_THROW_ON_ERROR);
        $decoded['alg'] = 'HS256';
        $this->expectException(CryptoSsoException::class);
        (new ProfileSigningKeyVerifier())->validatePublicJwk(json_encode($decoded, JSON_THROW_ON_ERROR));
    }

    /** @return array{0: \OpenSSLAsymmetricKey, 1: string} */
    private function keyPair(): array
    {
        $privateKey = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        $details = openssl_pkey_get_details($privateKey);
        $jwk = json_encode([
            'crv' => 'P-256',
            'ext' => true,
            'key_ops' => ['verify'],
            'kty' => 'EC',
            'x' => $this->base64Url($details['ec']['x']),
            'y' => $this->base64Url($details['ec']['y']),
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

        return [$privateKey, $jwk];
    }

    private function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
