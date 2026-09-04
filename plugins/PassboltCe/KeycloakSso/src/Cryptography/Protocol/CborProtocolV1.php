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
            $uuid = '/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/D';
            if (preg_match($uuid, $context[$field]) !== 1) {
                throw new InvalidArgumentException(sprintf('%s must be a canonical lowercase UUID.', $field));
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

    /** @param array<string, mixed> $context */
    public static function encodeEnrollmentTranscript(
        array $context,
        string $clientBlobDigest,
        string $serverShareDigest
    ): string {
        return self::encodeFixedTranscript('enrollment_transcript', $context, [
            $clientBlobDigest,
            $serverShareDigest,
        ]);
    }

    /** @param array<string, mixed> $context */
    public static function encodeDeviceLoginTranscript(
        array $context,
        string $clientNonce,
        string $hpkeRecipientPublicKey,
        string $clientBlobDigest
    ): string {
        return self::encodeFixedTranscript('device_login', $context, [
            $clientNonce,
            $hpkeRecipientPublicKey,
            $clientBlobDigest,
        ]);
    }

    /** @param array<string, mixed> $context */
    public static function encodeReleasePackageTranscript(
        array $context,
        string $clientNonce,
        string $hpkeRecipientPublicKey,
        string $requestId
    ): string {
        return self::encodeFixedTranscript('release_package', $context, [
            $clientNonce,
            $hpkeRecipientPublicKey,
            $requestId,
        ]);
    }

    /** @return array{context: array<string, string>, values: list<string>} */
    public static function decodeEnrollmentTranscript(string $encoded): array
    {
        return self::decodeFixedTranscript($encoded, 'enrollment_transcript', 2);
    }

    /** @return array{context: array<string, string>, values: list<string>} */
    public static function decodeDeviceLoginTranscript(string $encoded): array
    {
        return self::decodeFixedTranscript($encoded, 'device_login', 3);
    }

    /** @return array{context: array<string, string>, values: list<string>} */
    public static function decodeReleasePackageTranscript(string $encoded): array
    {
        return self::decodeFixedTranscript($encoded, 'release_package', 3);
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
        $context = self::contextFromObject($decoded);
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

    /**
     * @param array<string, mixed> $context
     * @param list<string> $requestValues
     */
    private static function encodeFixedTranscript(string $binding, array $context, array $requestValues): string
    {
        $values = [];
        foreach ($requestValues as $value) {
            if ($value === '' || !mb_check_encoding($value, 'UTF-8')) {
                throw new InvalidArgumentException('Transcript values must be non-empty UTF-8 text strings.');
            }
            $values[] = TextStringObject::create($value);
        }

        return (string)ListObject::create([
            ListObject::create([
                TextStringObject::create(self::DOMAINS[$binding]),
                self::contextObject($context),
            ]),
            ListObject::create($values),
        ]);
    }

    /** @return array{context: array<string, string>, values: list<string>} */
    private static function decodeFixedTranscript(string $encoded, string $binding, int $valueCount): array
    {
        if ($encoded === '' || strlen($encoded) > self::MAX_CONTEXT_BYTES * 2) {
            throw new InvalidArgumentException('Encoded transcript size is invalid.');
        }
        $decoded = Decoder::create(maxDepth: 4)->decode(StringStream::create($encoded));
        if (get_class($decoded) !== ListObject::class || count($decoded) !== 2) {
            throw new InvalidArgumentException('Encoded transcript does not match its fixed schema.');
        }
        $domainBinding = $decoded->get(0);
        $valuesObject = $decoded->get(1);
        if (
            get_class($domainBinding) !== ListObject::class || count($domainBinding) !== 2 ||
            get_class($valuesObject) !== ListObject::class || count($valuesObject) !== $valueCount
        ) {
            throw new InvalidArgumentException('Encoded transcript does not match its fixed schema.');
        }
        $domain = $domainBinding->get(0);
        $contextObject = $domainBinding->get(1);
        if (
            get_class($domain) !== TextStringObject::class ||
            !hash_equals(self::DOMAINS[$binding], $domain->getValue()) ||
            get_class($contextObject) !== ListObject::class || count($contextObject) !== count(self::FIELDS)
        ) {
            throw new InvalidArgumentException('Encoded transcript domain binding is invalid.');
        }
        $values = [];
        for ($index = 0; $index < $valueCount; $index++) {
            $value = $valuesObject->get($index);
            if (get_class($value) !== TextStringObject::class || $value->getValue() === '') {
                throw new InvalidArgumentException('Encoded transcript contains an invalid value.');
            }
            $values[] = $value->getValue();
        }
        $context = self::contextFromObject($contextObject);
        $reencoded = self::encodeFixedTranscript($binding, $context, $values);
        if (!hash_equals($encoded, $reencoded)) {
            throw new InvalidArgumentException('Encoded transcript is not its deterministic representation.');
        }

        return ['context' => $context, 'values' => $values];
    }

    /** @return array<string, string> */
    private static function contextFromObject(ListObject $object): array
    {
        $context = [];
        foreach (self::FIELDS as $index => $field) {
            $value = $object->get($index);
            if (get_class($value) !== TextStringObject::class) {
                throw new InvalidArgumentException('Encoded context contains a non-text value.');
            }
            $context[$field] = $value->getValue();
        }
        self::validate($context);

        return $context;
    }

    /**
     * Require a canonical public HTTPS Passbolt origin.
     */
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
