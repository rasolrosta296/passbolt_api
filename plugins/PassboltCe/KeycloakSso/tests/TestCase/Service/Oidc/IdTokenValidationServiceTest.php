<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Service\Oidc;

use Cake\TestSuite\TestCase;
use Firebase\JWT\JWT;
use OpenSSLAsymmetricKey;
use Passbolt\KeycloakSso\Error\Exception\OidcValidationException;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;
use Passbolt\KeycloakSso\Service\Oidc\IdTokenValidationService;
use Passbolt\KeycloakSso\Test\Utility\StaticJwksProvider;
use PHPUnit\Framework\Attributes\DataProvider;

final class IdTokenValidationServiceTest extends TestCase
{
    private const KID = 'test-signing-key';
    private const NONCE = 'expected-nonce';

    private OpenSSLAsymmetricKey $privateKey;
    /**
     * @var array<string, mixed>
     */
    private array $jwk;
    private int $now;

    protected function setUp(): void
    {
        parent::setUp();
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $key);
        $this->privateKey = $key;
        $details = openssl_pkey_get_details($key);
        $this->assertIsArray($details);
        $this->jwk = [
            'kty' => 'RSA',
            'kid' => self::KID,
            'use' => 'sig',
            'alg' => 'RS256',
            'n' => self::base64Url($details['rsa']['n']),
            'e' => self::base64Url($details['rsa']['e']),
        ];
        $this->now = time();
    }

    public function testValidToken(): void
    {
        $identity = $this->service()->validate(
            $this->token($this->validClaims()),
            hash('sha256', self::NONCE),
            $this->now
        );

        $this->assertSame('immutable-subject', $identity->subject);
        $this->assertSame('user@example.com', $identity->email);
    }

    public function testReturnsStrictReleaseFreshnessClaims(): void
    {
        $claims = $this->validClaims() + [
            'auth_time' => $this->now,
            'acr' => 'urn:keycloak:acr:mfa',
            'amr' => ['pwd', 'otp'],
        ];
        $identity = $this->service()->validate(
            $this->token($claims),
            hash('sha256', self::NONCE),
            $this->now
        );

        $this->assertSame($this->now, $identity->authTime);
        $this->assertSame('urn:keycloak:acr:mfa', $identity->acr);
        $this->assertSame(['pwd', 'otp'], $identity->amr);
    }

    /** @param callable(array<string, mixed>): array<string, mixed> $mutation */
    #[DataProvider('invalidClaimsProvider')]
    public function testRejectsInvalidClaims(callable $mutation, string $reason): void
    {
        $claims = $mutation($this->validClaims());

        try {
            $this->service()->validate($this->token($claims), hash('sha256', self::NONCE), $this->now);
            $this->fail('Expected OIDC validation to fail.');
        } catch (OidcValidationException $exception) {
            $this->assertSame($reason, $exception->reasonCode());
        }
    }

    public static function invalidClaimsProvider(): array
    {
        return [
            'incorrect issuer' => [self::set('iss', 'https://keyclock.gobaz.ir/realms/other'), 'issuer_mismatch'],
            'incorrect audience' => [self::set('aud', 'other-client'), 'audience_mismatch'],
            'missing azp' => [self::remove('azp', self::set('aud', ['passbolt', 'other'])), 'authorized_party_missing'],
            'incorrect azp' => [self::set('azp', 'other-client'), 'authorized_party_mismatch'],
            'expired' => [self::set('exp', 1), 'invalid_signature_or_token'],
            'missing exp' => [self::remove('exp'), 'token_expired_or_missing_exp'],
            'missing iat' => [self::remove('iat'), 'missing_or_invalid_iat'],
            'old iat' => [self::setRelative('iat', -301), 'old_iat'],
            'future iat' => [self::setRelative('iat', 61), 'invalid_signature_or_token'],
            'invalid nbf' => [self::setRelative('nbf', 61), 'invalid_signature_or_token'],
            'nonce mismatch' => [self::set('nonce', 'wrong'), 'nonce_mismatch'],
            'email false' => [self::set('email_verified', false), 'email_not_verified'],
            'email missing' => [self::remove('email_verified'), 'email_not_verified'],
            'email non-boolean' => [self::set('email_verified', 'true'), 'email_not_verified'],
            'malformed email' => [self::set('email', 'not-an-email'), 'invalid_email'],
            'auth time string' => [self::set('auth_time', '1'), 'invalid_auth_time'],
            'acr non-string' => [self::set('acr', 1), 'invalid_acr'],
            'amr non-list' => [self::set('amr', ['method' => 'pwd']), 'invalid_amr'],
            'amr non-string member' => [self::set('amr', ['pwd', 1]), 'invalid_amr'],
        ];
    }

    public function testRejectsInvalidSignature(): void
    {
        $otherKey = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $otherKey);

        $this->expectException(OidcValidationException::class);
        $this->service()->validate(
            JWT::encode($this->validClaims(), $otherKey, 'RS256', self::KID),
            hash('sha256', self::NONCE),
            $this->now
        );
    }

    public function testRejectsAlgNoneBeforeSignatureProcessing(): void
    {
        $header = self::base64Url(json_encode(['alg' => 'none', 'kid' => self::KID], JSON_THROW_ON_ERROR));
        $payload = self::base64Url(json_encode($this->validClaims(), JSON_THROW_ON_ERROR));

        try {
            $this->service()->validate($header . '.' . $payload . '.', hash('sha256', self::NONCE), $this->now);
            $this->fail('Expected OIDC validation to fail.');
        } catch (OidcValidationException $exception) {
            $this->assertSame('disallowed_algorithm', $exception->reasonCode());
        }
    }

    public function testRejectsAlgorithmConfusion(): void
    {
        $header = self::base64Url(json_encode(['alg' => 'HS256', 'kid' => self::KID], JSON_THROW_ON_ERROR));
        $payload = self::base64Url(json_encode($this->validClaims(), JSON_THROW_ON_ERROR));
        $signature = self::base64Url(hash_hmac('sha256', $header . '.' . $payload, 'attacker-key', true));

        try {
            $this->service()->validate(
                $header . '.' . $payload . '.' . $signature,
                hash('sha256', self::NONCE),
                $this->now
            );
            $this->fail('Expected OIDC validation to fail.');
        } catch (OidcValidationException $exception) {
            $this->assertSame('disallowed_algorithm', $exception->reasonCode());
        }
    }

    public function testRefreshesJwksOnceForUnknownKid(): void
    {
        $provider = new StaticJwksProvider(['keys' => [$this->withKid($this->jwk, 'old')]], ['keys' => [$this->jwk]]);
        $service = new IdTokenValidationService($this->configuration(), $provider);

        $service->validate($this->token($this->validClaims()), hash('sha256', self::NONCE), $this->now);

        $this->assertSame(1, $provider->normalCalls);
        $this->assertSame(1, $provider->refreshCalls);
    }

    public function testRejectsTokenControlledJku(): void
    {
        $token = JWT::encode($this->validClaims(), $this->privateKey, 'RS256', self::KID, [
            'jku' => 'https://evil.example/jwks',
        ]);

        try {
            $this->service()->validate($token, hash('sha256', self::NONCE), $this->now);
            $this->fail('Expected OIDC validation to fail.');
        } catch (OidcValidationException $exception) {
            $this->assertSame('untrusted_key_reference', $exception->reasonCode());
        }
    }

    private function service(): IdTokenValidationService
    {
        return new IdTokenValidationService($this->configuration(), new StaticJwksProvider(['keys' => [$this->jwk]]));
    }

    private function configuration(): OidcConfigurationDto
    {
        return new OidcConfigurationDto(
            'https://keyclock.gobaz.ir/realms/passbolt',
            'passbolt',
            'secret',
            'https://passbolt.gobaz.ir/auth/keycloak/callback',
            random_bytes(32)
        );
    }

    /** @return array<string, mixed> */
    private function validClaims(): array
    {
        return [
            'iss' => 'https://keyclock.gobaz.ir/realms/passbolt',
            'aud' => 'passbolt',
            'azp' => 'passbolt',
            'exp' => $this->now + 120,
            'iat' => $this->now,
            'nonce' => self::NONCE,
            'sub' => 'immutable-subject',
            'email' => 'user@example.com',
            'email_verified' => true,
        ];
    }

    /** @param array<string, mixed> $claims */
    private function token(array $claims): string
    {
        return JWT::encode($claims, $this->privateKey, 'RS256', self::KID);
    }

    /** @param array<string, mixed> $jwk @return array<string, mixed> */
    private function withKid(array $jwk, string $kid): array
    {
        $jwk['kid'] = $kid;

        return $jwk;
    }

    private static function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    private static function set(string $field, mixed $value): callable
    {
        return static function (array $claims) use ($field, $value): array {
            $claims[$field] = $value;

            return $claims;
        };
    }

    private static function setRelative(string $field, int $offset): callable
    {
        return static function (array $claims) use ($field, $offset): array {
            $claims[$field] = time() + $offset;

            return $claims;
        };
    }

    private static function remove(string $field, ?callable $before = null): callable
    {
        return static function (array $claims) use ($field, $before): array {
            if ($before !== null) {
                $claims = $before($claims);
            }
            unset($claims[$field]);

            return $claims;
        };
    }
}
