<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Service\Oidc;

use Cake\Http\Cookie\Cookie;
use Cake\TestSuite\TestCase;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;
use Passbolt\KeycloakSso\Service\Oidc\OidcCookieService;

final class OidcCookieServiceTest extends TestCase
{
    public function testBrowserBindingUsesHostPrefixAndSecureCookieAttributes(): void
    {
        $cookie = OidcCookieService::browserBinding(str_repeat('b', 43));

        $this->assertStringStartsWith('__Host-', $cookie->getName());
        $this->assertSame('/', $cookie->getPath());
        $this->assertTrue($cookie->isSecure());
        $this->assertTrue($cookie->isHttpOnly());
        $this->assertSame('Lax', $cookie->getSameSite()?->value);
        $this->assertSame('', $cookie->getDomain());
    }

    public function testPurposeSpecificResultCookieLifetimes(): void
    {
        $this->assertSame(60, OidcConfigurationDto::RESULT_TTL_SECONDS);
        $this->assertSame(300, OidcConfigurationDto::IDENTITY_LINK_RESULT_TTL_SECONDS);
        $this->assertSame(300, OidcConfigurationDto::CRYPTO_RESULT_TTL_SECONDS);
        $this->assertCookieTtl(
            OidcCookieService::result(str_repeat('r', 43)),
            OidcConfigurationDto::RESULT_TTL_SECONDS
        );
        $this->assertCookieTtl(
            OidcCookieService::linkResult(str_repeat('l', 43)),
            OidcConfigurationDto::IDENTITY_LINK_RESULT_TTL_SECONDS
        );
        $this->assertCookieTtl(
            OidcCookieService::cryptoResult(str_repeat('c', 43)),
            OidcConfigurationDto::CRYPTO_RESULT_TTL_SECONDS
        );
    }

    private function assertCookieTtl(Cookie $cookie, int $expectedTtl): void
    {
        $expiry = $cookie->getExpiry();
        $this->assertNotNull($expiry);
        $this->assertEqualsWithDelta(time() + $expectedTtl, $expiry->getTimestamp(), 1);
    }
}
