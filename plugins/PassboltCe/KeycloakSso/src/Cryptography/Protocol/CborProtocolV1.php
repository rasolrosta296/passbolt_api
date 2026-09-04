<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Cryptography\Protocol;

use CBOR\Decoder;
use CBOR\ListObject;
use CBOR\StringStream;
use CBOR\TextStringObject;
use InvalidArgumentException;

final class CborProtocolV1
{
    public const VERSION = 'passbolt-keycloak-sso-v1';
    public const SUITE = 'AES-256-GCM+HPKE-P256-HKDF-SHA256-AES128GCM';

    public const FIELDS = [
        'protocol_version',
        'crypto_suite',
        'passbolt_origin',
        'user_uuid',
        'identity_uuid',
        'enrollment_uuid',
        'client_enrollment_uuid',
        'openpgp_fingerprint',
        'enrollment_public_key_thumbprint',
    ];

    public const DOMAINS = [
        'inner_aad' => 'passbolt-keycloak-sso-v1/inner-aead',
        'outer_aad' => 'passbolt-keycloak-sso-v1/outer-aead',
        'enrollment_transcript' => 'passbolt-keycloak-sso-v1/enrollment-transcript',
        'device_login' => 'passbolt-keycloak-sso-v1/device-login',
        'release_package' => 'passbolt-keycloak-sso-v1/release-package',
        'context_hash' => 'passbolt-keycloak-sso-v1/context-hash',
    ];

    public const MAX_CONTEXT_BYTES = 2048;

    /** @param array<string, mixed> $context */
    public static function validate(array $context): void
    {
        if (array_keys($context) !== self::FIELDS) {
            throw new InvalidArgumentException('Context must contain exactly the ordered version-one fields.');
        }
        foreach (self::FIELDS as $field) {
            if (!is_string($context[$field]) || !mb_check_encoding($context[$field], 'UTF-8')) {
                throw new InvalidArgumentException(sprintf('%s must be a valid UTF-8 text string.', $field));
            }
        }
        if (!hash_equals(self::VERSION, $context['protocol_version'])) {
            throw new InvalidArgumentException('Unsupported protocol version.');
        }
        if (!hash_equals(self::SUITE, $context['crypto_suite'])) {
            throw new InvalidArgumentException('Unsupported cryptographic suite.');
        }
        self::assertOrigin($context['passbolt_origin']);
        foreach (['user_uuid', 'identity_uuid', 'enrollment_uuid', 'client_enrollment_uuid'] as $field) {
            if (preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/D', $context[$field]) !== 1) {
                throw new InvalidArgumentException(sprintf('%s must be a canonical lowercase UUIDv4.', $field));
            }
        }
        if (preg_match('/^[0-9A-F]{40}$/D', $context['openpgp_fingerprint']) !== 1) {
            throw new InvalidArgumentException('OpenPGP fingerprint must be uppercase hexadecimal.');
        }
        if (preg_match('/^[A-Za-z0-9_-]{43}$/D', $context['enrollment_public_key_thumbprint']) !== 1) {
            throw new InvalidArgumentException('Enrollment public-key thumbprint is invalid.');
        }
    }

    /** @param array<string, mixed> $context */
    public static function encodeContext(array $context): string
    {
        return (string)self::contextObject($context);
    }

    /** @param array<string, mixed> $context */
    public static function encodeBinding(string $binding, array $context): string
    {
        if (!array_key_exists($binding, self::DOMAINS)) {
            throw new InvalidArgumentException('Unknown protocol domain.');
        }

        return (string)ListObject::create([
            TextStringObject::create(self::DOMAINS[$binding]),
            self::contextObject($context),
        ]);
    }

    /**
     * Encode a signature transcript that binds request-specific public data to an approved domain.
     *
     * @param array<string, mixed> $context
     * @param list<string> $requestValues
     */
    public static function encodeTranscript(string $binding, array $context, array $requestValues = []): string
    {
        if (!array_key_exists($binding, self::DOMAINS)) {
            throw new InvalidArgumentException('Unknown protocol domain.');
        }
        $items = [TextStringObject::create(self::DOMAINS[$binding]), self::contextObject($context)];
        foreach ($requestValues as $value) {
            if (!is_string($value) || !mb_check_encoding($value, 'UTF-8')) {
                throw new InvalidArgumentException('Transcript request values must be valid UTF-8 text strings.');
            }
            $items[] = TextStringObject::create($value);
        }

        return (string)ListObject::create($items);
    }

    /** @return array<string, string> */
    public static function decodeContext(string $encoded): array
    {
        if ($encoded === '' || strlen($encoded) > self::MAX_CONTEXT_BYTES) {
            throw new InvalidArgumentException('Encoded context size is invalid.');
        }
        $decoded = Decoder::create(maxDepth: 2)->decode(StringStream::create($encoded));
        if (get_class($decoded) !== ListObject::class || count($decoded) !== count(self::FIELDS)) {
            throw new InvalidArgumentException('Encoded context does not match the fixed array schema.');
        }
        $context = [];
        foreach (self::FIELDS as $index => $field) {
            $value = $decoded->get($index);
            if (get_class($value) !== TextStringObject::class) {
                throw new InvalidArgumentException('Encoded context contains a non-text value.');
            }
            $context[$field] = $value->getValue();
        }
        self::validate($context);
        if (!hash_equals($encoded, self::encodeContext($context))) {
            throw new InvalidArgumentException('Encoded context is not its deterministic representation.');
        }

        return $context;
    }

    /** @param array<string, mixed> $context */
    public static function contextHash(array $context): string
    {
        return hash('sha256', self::encodeBinding('context_hash', $context));
    }

    /** @param array<string, mixed> $context */
    private static function contextObject(array $context): ListObject
    {
        self::validate($context);
        $items = [];
        foreach (self::FIELDS as $field) {
            $items[] = TextStringObject::create($context[$field]);
        }

        return ListObject::create($items);
    }

    private static function assertOrigin(string $origin): void
    {
        if (strlen($origin) > 255) {
            throw new InvalidArgumentException('Passbolt origin is too long.');
        }
        $parts = parse_url($origin);
        if (
            !is_array($parts) || ($parts['scheme'] ?? null) !== 'https' || !isset($parts['host']) ||
            isset($parts['user']) || isset($parts['pass']) || isset($parts['path']) ||
            isset($parts['query']) || isset($parts['fragment'])
        ) {
            throw new InvalidArgumentException('Passbolt origin must be a canonical absolute HTTPS origin.');
        }
        $host = $parts['host'];
        $labels = explode('.', $host);
        if (strlen($host) > 253 || strtolower($host) !== $host || count($labels) < 2) {
            throw new InvalidArgumentException('Passbolt origin host is not canonical ASCII DNS.');
        }
        foreach ($labels as $label) {
            if (preg_match('/^(?!-)[a-z0-9-]{1,63}(?<!-)$/D', $label) !== 1) {
                throw new InvalidArgumentException('Passbolt origin host is not canonical ASCII DNS.');
            }
        }
        $port = $parts['port'] ?? null;
        if ($port === 443) {
            throw new InvalidArgumentException('The default HTTPS port must be omitted.');
        }
        $canonical = 'https://' . $host . ($port === null ? '' : ':' . $port);
        if (!hash_equals($canonical, $origin)) {
            throw new InvalidArgumentException('Passbolt origin is not canonical.');
        }
    }
}
