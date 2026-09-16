<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Utility\Http;

use Cake\TestSuite\TestCase;
use Passbolt\KeycloakSso\Utility\Http\SystemHostResolver;
use RuntimeException;

final class SystemHostResolverTest extends TestCase
{
    public function testResolvesAAndAaaaRecordsSeparatelyWithoutFallback(): void
    {
        $fallbackCalled = false;
        $resolver = new SystemHostResolver(
            static fn (string $_host, int $type): array => match ($type) {
                DNS_A => [['ip' => '198.51.100.10'], ['ip' => '198.51.100.10']],
                DNS_AAAA => [['ipv6' => '2001:db8::10']],
            },
            static function (string $_host) use (&$fallbackCalled): array {
                $fallbackCalled = true;

                return ['198.51.100.20'];
            }
        );

        $this->assertSame(['198.51.100.10', '2001:db8::10'], $resolver->resolve('oidc.example'));
        $this->assertFalse($fallbackCalled);
    }

    public function testUsesSystemIpv4ResolverWhenDirectDnsReturnsNoAddresses(): void
    {
        $resolver = new SystemHostResolver(
            static fn (string $_host, int $_type): array => [],
            static fn (string $_host): array => ['198.51.100.20', '198.51.100.20']
        );

        $this->assertSame(['198.51.100.20'], $resolver->resolve('oidc.example'));
    }

    public function testReturnsNoAddressesWhenDirectAndFallbackResolutionFail(): void
    {
        $resolver = new SystemHostResolver(
            static fn (string $_host, int $_type): false => false,
            static fn (string $_host): false => false
        );

        $this->assertSame([], $resolver->resolve('oidc.example'));
    }

    public function testIpLiteralDoesNotInvokeResolvers(): void
    {
        $resolver = new SystemHostResolver(
            static function (string $_host, int $_type): array {
                throw new RuntimeException('Direct DNS must not be called for an IP literal.');
            },
            static function (string $_host): array {
                throw new RuntimeException('Fallback DNS must not be called for an IP literal.');
            }
        );

        $this->assertSame(['198.51.100.30'], $resolver->resolve('198.51.100.30'));
    }
}
