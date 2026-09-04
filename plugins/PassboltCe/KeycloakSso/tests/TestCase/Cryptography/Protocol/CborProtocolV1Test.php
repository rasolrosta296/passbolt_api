<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Cryptography\Protocol;

use InvalidArgumentException;
use Passbolt\KeycloakSso\Cryptography\Protocol\CborProtocolV1;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class CborProtocolV1Test extends TestCase
{
    public function testApprovedVectorAndBindings(): void
    {
        $fixture = $this->fixture();
        $context = $fixture['context'];
        $encoded = CborProtocolV1::encodeContext($context);
        $this->assertVector($fixture['vectors']['context'], $encoded);
        $this->assertSame($context, CborProtocolV1::decodeContext($encoded));

        $this->assertVector($fixture['vectors']['inner_aad'], CborProtocolV1::encodeBinding('inner_aad', $context));
        $this->assertVector($fixture['vectors']['outer_aad'], CborProtocolV1::encodeBinding('outer_aad', $context));
        $this->assertVector(
            $fixture['vectors']['context_hash'],
            CborProtocolV1::encodeBinding('context_hash', $context)
        );
    }

    public function testApprovedFixedTranscriptVectors(): void
    {
        $fixture = $this->fixture();
        $context = $fixture['context'];
        $values = $fixture['values'];
        $enrollment = CborProtocolV1::encodeEnrollmentTranscript(
            $context,
            $values['client_blob_digest'],
            $values['server_share_digest']
        );
        $login = CborProtocolV1::encodeDeviceLoginTranscript(
            $context,
            $values['client_nonce'],
            $values['hpke_recipient_public_key'],
            $values['client_blob_digest']
        );
        $release = CborProtocolV1::encodeReleasePackageTranscript(
            $context,
            $values['client_nonce'],
            $values['hpke_recipient_public_key'],
            $values['request_id']
        );

        $this->assertVector($fixture['vectors']['enrollment_transcript'], $enrollment);
        $this->assertVector($fixture['vectors']['device_login_transcript'], $login);
        $this->assertVector($fixture['vectors']['release_package_transcript'], $release);
        $this->assertSame(
            [$values['client_blob_digest'], $values['server_share_digest']],
            CborProtocolV1::decodeEnrollmentTranscript($enrollment)['values']
        );
        $this->assertSame([$values['client_nonce'], $values['hpke_recipient_public_key'],
            $values['client_blob_digest']], CborProtocolV1::decodeDeviceLoginTranscript($login)['values']);
        $this->assertSame(
            [$values['client_nonce'], $values['hpke_recipient_public_key'], $values['request_id']],
            CborProtocolV1::decodeReleasePackageTranscript($release)['values']
        );
    }

    public function testTranscriptDecoderRejectsAlternateSchemaAndTrailingBytes(): void
    {
        $fixture = $this->fixture();
        $encoded = base64_decode($fixture['vectors']['enrollment_transcript']['base64'], true);
        $this->expectException(InvalidArgumentException::class);
        CborProtocolV1::decodeEnrollmentTranscript($encoded . "\x00");
    }

    #[DataProvider('invalidEncodedProvider')]
    public function testRejectsMalformedOrNonCanonicalEncoding(string $hex): void
    {
        $this->expectException(InvalidArgumentException::class);
        CborProtocolV1::decodeContext((string)hex2bin($hex));
    }

    public static function invalidEncodedProvider(): array
    {
        return [
            'map' => ['a0'],
            'indefinite array' => ['9fff'],
            'trailing bytes' => ['80ff'],
            'integer item' => ['89000000000000000000'],
        ];
    }

    /** @param array{base64: string, sha256: string} $vector */
    private function assertVector(array $vector, string $actual): void
    {
        $this->assertSame($vector['base64'], base64_encode($actual));
        $this->assertSame($vector['sha256'], hash('sha256', $actual));
    }

    /** @return array<string, mixed> */
    private function fixture(): array
    {
        $contents = file_get_contents(dirname(__DIR__, 3) . '/Fixture/protocol-v1-vectors.json');

        return json_decode((string)$contents, true, 16, JSON_THROW_ON_ERROR);
    }
}
