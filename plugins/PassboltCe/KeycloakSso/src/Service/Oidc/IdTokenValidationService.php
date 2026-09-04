<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Oidc;

use App\Model\Validation\EmailValidationRule;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Passbolt\KeycloakSso\Error\Exception\OidcValidationException;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;
use Passbolt\KeycloakSso\Model\Dto\ValidatedOidcIdentity;
use SensitiveParameter;
use stdClass;
use Throwable;

final class IdTokenValidationService
{
    /**
     * Construct the validator with fixed configuration and trusted JWKS.
     */
    public function __construct(
        private readonly OidcConfigurationDto $configuration,
        private readonly JwksProviderInterface $jwksProvider,
    ) {
    }

    /**
     * Validate an ID token and return only the identity claims needed by this milestone.
     */
    public function validate(
        #[SensitiveParameter]
        string $idToken,
        string $expectedNonceHash,
        ?int $now = null
    ): ValidatedOidcIdentity {
        if (
            $idToken === '' || strlen($idToken) > 32_768 ||
            !preg_match('/^[a-f0-9]{64}$/', $expectedNonceHash)
        ) {
            throw new OidcValidationException('malformed_id_token');
        }
        $now ??= time();
        $header = $this->parseHeader($idToken);
        $kid = $this->assertHeader($header);
        $jwks = $this->jwksProvider->get();
        if (!$this->containsKid($jwks, $kid)) {
            $jwks = $this->jwksProvider->get(true);
            if (!$this->containsKid($jwks, $kid)) {
                throw new OidcValidationException('unknown_signing_key');
            }
        }

        $previousLeeway = JWT::$leeway;
        $previousTimestamp = JWT::$timestamp;
        try {
            JWT::$leeway = OidcConfigurationDto::CLOCK_SKEW_SECONDS;
            JWT::$timestamp = $now;
            $claims = (array)JWT::decode($idToken, JWK::parseKeySet($jwks, 'RS256'));
        } catch (Throwable) {
            throw new OidcValidationException('invalid_signature_or_token');
        } finally {
            JWT::$leeway = $previousLeeway;
            JWT::$timestamp = $previousTimestamp;
        }

        $this->assertIssuer($claims);
        $this->assertAudience($claims);
        $this->assertTimes($claims, $now);
        $this->assertNonce($claims, $expectedNonceHash);

        $subject = $claims['sub'] ?? null;
        if (
            !is_string($subject) || $subject === '' || strlen($subject) > 255 ||
            preg_match('/[\x00-\x1F\x7F]/', $subject)
        ) {
            throw new OidcValidationException('invalid_subject');
        }
        $email = $claims['email'] ?? null;
        if (
            !is_string($email) || $email === '' || $email !== trim($email) || strlen($email) > 254 ||
            !EmailValidationRule::check($email, true)
        ) {
            throw new OidcValidationException('invalid_email');
        }
        if (!array_key_exists('email_verified', $claims) || $claims['email_verified'] !== true) {
            throw new OidcValidationException('email_not_verified');
        }

        $authTime = $claims['auth_time'] ?? null;
        $acr = $claims['acr'] ?? null;
        $amr = $claims['amr'] ?? [];
        if ($authTime !== null && !is_int($authTime)) {
            throw new OidcValidationException('invalid_auth_time');
        }
        if ($acr !== null && (!is_string($acr) || $acr === '' || strlen($acr) > 255)) {
            throw new OidcValidationException('invalid_acr');
        }
        if (!is_array($amr) || !array_is_list($amr)) {
            throw new OidcValidationException('invalid_amr');
        }
        foreach ($amr as $method) {
            if (!is_string($method) || $method === '' || strlen($method) > 64) {
                throw new OidcValidationException('invalid_amr');
            }
        }

        return new ValidatedOidcIdentity($subject, $email, $authTime, $acr, $amr);
    }

    /**
     * Parse only the JOSE header needed to select a trusted key.
     */
    private function parseHeader(string $idToken): stdClass
    {
        try {
            $segments = explode('.', $idToken);
            if (count($segments) !== 3) {
                throw new OidcValidationException('malformed_id_token');
            }
            $header = JWT::jsonDecode(JWT::urlsafeB64Decode($segments[0]));
            if (!($header instanceof stdClass)) {
                throw new OidcValidationException('malformed_id_token');
            }

            return $header;
        } catch (OidcValidationException $exception) {
            throw $exception;
        } catch (Throwable) {
            throw new OidcValidationException('malformed_id_token');
        }
    }

    /**
     * Enforce the algorithm allowlist and reject token-controlled key URLs.
     */
    private function assertHeader(stdClass $header): string
    {
        if (
            !isset($header->alg) || !is_string($header->alg) ||
            !in_array($header->alg, OidcConfigurationDto::ALLOWED_ID_TOKEN_ALGORITHMS, true)
        ) {
            throw new OidcValidationException('disallowed_algorithm');
        }
        if (isset($header->jku) || isset($header->x5u) || isset($header->jwk) || isset($header->x5c)) {
            throw new OidcValidationException('untrusted_key_reference');
        }
        if (isset($header->crit)) {
            throw new OidcValidationException('unsupported_critical_header');
        }
        if (!isset($header->kid) || !is_string($header->kid) || $header->kid === '' || strlen($header->kid) > 255) {
            throw new OidcValidationException('invalid_key_id');
        }

        return $header->kid;
    }

    /** @param array{keys: list<array<string, mixed>>} $jwks */
    private function containsKid(array $jwks, string $kid): bool
    {
        foreach ($jwks['keys'] as $key) {
            if (($key['kid'] ?? null) === $kid) {
                return true;
            }
        }

        return false;
    }

    /** @param array<string, mixed> $claims */
    private function assertIssuer(array $claims): void
    {
        if (
            !isset($claims['iss']) || !is_string($claims['iss']) ||
            !hash_equals($this->configuration->issuer, $claims['iss'])
        ) {
            throw new OidcValidationException('issuer_mismatch');
        }
    }

    /** @param array<string, mixed> $claims */
    private function assertAudience(array $claims): void
    {
        $audience = $claims['aud'] ?? null;
        $audiences = is_string($audience) ? [$audience] : $audience;
        if (!is_array($audiences) || $audiences === [] || !in_array($this->configuration->clientId, $audiences, true)) {
            throw new OidcValidationException('audience_mismatch');
        }
        foreach ($audiences as $value) {
            if (!is_string($value) || $value === '') {
                throw new OidcValidationException('audience_mismatch');
            }
        }

        $azp = $claims['azp'] ?? null;
        if (count($audiences) > 1 && !is_string($azp)) {
            throw new OidcValidationException('authorized_party_missing');
        }
        if ($azp !== null && (!is_string($azp) || !hash_equals($this->configuration->clientId, $azp))) {
            throw new OidcValidationException('authorized_party_mismatch');
        }
    }

    /** @param array<string, mixed> $claims */
    private function assertTimes(array $claims, int $now): void
    {
        $exp = $claims['exp'] ?? null;
        $iat = $claims['iat'] ?? null;
        if (!is_int($exp) || $exp <= $now - OidcConfigurationDto::CLOCK_SKEW_SECONDS) {
            throw new OidcValidationException('token_expired_or_missing_exp');
        }
        if (!is_int($iat)) {
            throw new OidcValidationException('missing_or_invalid_iat');
        }
        if ($iat > $now + OidcConfigurationDto::CLOCK_SKEW_SECONDS) {
            throw new OidcValidationException('future_iat');
        }
        if ($iat < $now - OidcConfigurationDto::MAX_ID_TOKEN_AGE_SECONDS) {
            throw new OidcValidationException('old_iat');
        }
        if (isset($claims['nbf'])) {
            if (!is_int($claims['nbf']) || $claims['nbf'] > $now + OidcConfigurationDto::CLOCK_SKEW_SECONDS) {
                throw new OidcValidationException('invalid_nbf');
            }
        }
    }

    /** @param array<string, mixed> $claims */
    private function assertNonce(array $claims, string $expectedNonceHash): void
    {
        $nonce = $claims['nonce'] ?? null;
        if (!is_string($nonce) || $nonce === '' || !hash_equals($expectedNonceHash, hash('sha256', $nonce))) {
            throw new OidcValidationException('nonce_mismatch');
        }
    }
}
