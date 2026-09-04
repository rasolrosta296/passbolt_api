<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Cryptography\Protocol;

use InvalidArgumentException;
use Passbolt\KeycloakSso\Cryptography\Protocol\CborProtocolV1;
use PHPUnit\Framework\TestCase;

final class CborProtocolV1Test extends TestCase
{
    public function testApprovedVectorAndBindings(): void
    {
        $context = $this->context();
        $expected = '89781870617373626f6c742d6b6579636c6f616b2d73736f2d7631' .
            '782b4145532d3235362d47434d2b48504b452d503235362d484b44462d5348413235362d41455331323847434d' .
            '781d68747470733a2f2f70617373626f6c742e6578616d706c652e74657374' .
            '782431303030303030302d303030302d343030302d383030302d303030303030303030303031' .
            '782432303030303030302d303030302d343030302d383030302d303030303030303030303032' .
            '782433303030303030302d303030302d343030302d383030302d303030303030303030303033' .
            '782434303030303030302d303030302d343030302d383030302d303030303030303030303034' .
            '782830313233343536373839414243444546303132333435363738394142434445463031323334353637' .
            '782b41414141414141414141414141414141414141414141414141414141414141414141414141414141414141';
        $encoded = CborProtocolV1::encodeContext($context);
        $this->assertSame($expected, bin2hex($encoded));
        $this->assertSame('b31273c52f4b1dd77242ce0dcbeb8fb500fabded5e14fdca53bc6d080d5d3ec5', hash('sha256', $encoded));
        $this->assertSame($context, CborProtocolV1::decodeContext($encoded));
    }

    /** @dataProvider invalidEncodedProvider */
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

    /** @return array<string, string> */
    private function context(): array
    {
        return [
            'protocol_version' => CborProtocolV1::VERSION,
            'crypto_suite' => CborProtocolV1::SUITE,
            'passbolt_origin' => 'https://passbolt.example.test',
            'user_uuid' => '10000000-0000-4000-8000-000000000001',
            'identity_uuid' => '20000000-0000-4000-8000-000000000002',
            'enrollment_uuid' => '30000000-0000-4000-8000-000000000003',
            'client_enrollment_uuid' => '40000000-0000-4000-8000-000000000004',
            'openpgp_fingerprint' => '0123456789ABCDEF0123456789ABCDEF01234567',
            'enrollment_public_key_thumbprint' => 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        ];
    }
}
