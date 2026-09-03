<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Service\Oidc;

use Cake\TestSuite\TestCase;
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
}
