<?php
declare(strict_types=1);

/**
 * Passbolt ~ Open source password manager for teams
 * Copyright (c) Passbolt SA (https://www.passbolt.com)
 *
 * Licensed under GNU Affero General Public License version 3 of the or any later version.
 * For full copyright and license information, please see the LICENSE.txt
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright     Copyright (c) Passbolt SA (https://www.passbolt.com)
 * @license       https://opensource.org/licenses/AGPL-3.0 AGPL License
 * @link          https://www.passbolt.com Passbolt(tm)
 * @since         5.7.0
 */

namespace App\Test\TestCase\Middleware;

use App\Middleware\ContentSecurityPolicyExtension;
use App\Middleware\ContentSecurityPolicyMiddleware;
use App\Test\Lib\Http\TestRequestHandler;
use Cake\Core\Configure;
use Cake\Http\Response;
use Cake\Http\ServerRequest;
use Cake\TestSuite\TestCase;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

#[CoversClass(ContentSecurityPolicyMiddleware::class)]
class ContentSecurityPolicyMiddlewareTest extends TestCase
{
    public function testContentSecurityPolicyMiddleware_Default_CSP()
    {
        $middleware = new ContentSecurityPolicyMiddleware();

        /** @var \Cake\Http\ServerRequest $response */
        $response = $middleware->process(new ServerRequest(), new TestRequestHandler());

        $cspHeaders = $response->getHeader('Content-Security-Policy');
        $expectedHeader = "default-src 'none';"
            . ' ' . "script-src 'self';"
            . ' ' . "style-src 'self';"
            . ' ' . "img-src 'self';"
            . ' ' . "font-src 'self';"
            . ' ' . "connect-src 'self';"
            . ' ' . "base-uri 'self';"
            . ' ' . "frame-src 'self';"
            . ' ' . "frame-ancestors 'none';"
            . ' ' . "form-action 'self' https://*.duosecurity.com";
        // CSP header should be in single line
        $this->assertCount(1, $cspHeaders);
        $this->assertSame($expectedHeader, $cspHeaders[0]);
    }

    public function testContentSecurityPolicyMiddleware_Config_Overwrite()
    {
        $csp = 'foo';
        Configure::write('passbolt.security.csp', $csp);
        $middleware = new ContentSecurityPolicyMiddleware();

        /** @var \Cake\Http\ServerRequest $response */
        $response = $middleware->process(new ServerRequest(), new TestRequestHandler());

        $cspHeaders = $response->getHeader('Content-Security-Policy');
        $this->assertSame([$csp], $cspHeaders);
    }

    public function testContentSecurityPolicyMiddleware_RequestScopedFormActionOrigin(): void
    {
        $middleware = new ContentSecurityPolicyMiddleware();
        $handler = new TestRequestHandler(function (ServerRequest $request): Response {
            $extension = $request->getAttribute(ContentSecurityPolicyMiddleware::EXTENSION_ATTRIBUTE);
            $this->assertInstanceOf(ContentSecurityPolicyExtension::class, $extension);
            $extension->addFormActionOrigin('https://login.example.test:443');

            return new Response();
        });

        $response = $middleware->process(new ServerRequest(), $handler);
        $headers = $response->getHeader('Content-Security-Policy');

        $this->assertCount(1, $headers);
        $this->assertSame($this->defaultCsp() . ' https://login.example.test', $headers[0]);
        $this->assertStringContainsString("form-action 'self' https://*.duosecurity.com", $headers[0]);
        $this->assertStringStartsWith("default-src 'none'; script-src 'self';", $headers[0]);
    }

    public function testContentSecurityPolicyMiddleware_PreservesNonDefaultHttpsPort(): void
    {
        $middleware = new ContentSecurityPolicyMiddleware();
        $handler = new TestRequestHandler(function (ServerRequest $request): Response {
            $extension = $request->getAttribute(ContentSecurityPolicyMiddleware::EXTENSION_ATTRIBUTE);
            $this->assertInstanceOf(ContentSecurityPolicyExtension::class, $extension);
            $extension->addFormActionOrigin('https://login.example.test:8443');

            return new Response();
        });

        $response = $middleware->process(new ServerRequest(), $handler);

        $this->assertSame([$this->defaultCsp() . ' https://login.example.test:8443'], $response->getHeader(
            'Content-Security-Policy'
        ));
    }

    #[DataProvider('invalidFormActionOriginProvider')]
    public function testContentSecurityPolicyExtension_RejectsInvalidOrigin(string $origin): void
    {
        $this->expectException(InvalidArgumentException::class);

        (new ContentSecurityPolicyExtension())->addFormActionOrigin($origin);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidFormActionOriginProvider(): array
    {
        return [
            'http' => ['http://login.example.test'],
            'credentials' => ['https://user:password@login.example.test'],
            'path' => ['https://login.example.test/realms/example'],
            'query' => ['https://login.example.test?issuer=evil'],
            'fragment' => ['https://login.example.test#fragment'],
            'wildcard' => ['https://*.example.test'],
            'malformed host' => ['https://not_a_host.example'],
            'not a URL' => ['not-an-origin'],
        ];
    }

    public function testContentSecurityPolicyMiddleware_RequestValuesCannotExtendPolicy(): void
    {
        $previous = getenv('KEYCLOAK_SSO_ENABLED');
        putenv('KEYCLOAK_SSO_ENABLED=false');
        try {
            $request = new ServerRequest([
                'url' => '/unrelated?issuer=https://evil.example',
                'environment' => ['HTTP_HOST' => 'evil.example'],
            ]);
            $response = (new ContentSecurityPolicyMiddleware())->process($request, new TestRequestHandler());

            $this->assertSame([$this->defaultCsp()], $response->getHeader('Content-Security-Policy'));
            $this->assertStringNotContainsString('evil.example', $response->getHeaderLine('Content-Security-Policy'));
        } finally {
            if ($previous === false) {
                putenv('KEYCLOAK_SSO_ENABLED');
            } else {
                putenv('KEYCLOAK_SSO_ENABLED=' . $previous);
            }
        }
    }

    public function testContentSecurityPolicyMiddleware_ExtendsConfiguredPolicyWithoutSecondHeader(): void
    {
        Configure::write('passbolt.security.csp', "default-src 'none'; form-action 'self'; frame-ancestors 'none'");
        $handler = new TestRequestHandler(function (ServerRequest $request): Response {
            $extension = $request->getAttribute(ContentSecurityPolicyMiddleware::EXTENSION_ATTRIBUTE);
            $this->assertInstanceOf(ContentSecurityPolicyExtension::class, $extension);
            $extension->addFormActionOrigin('https://login.example.test');

            return (new Response())->withHeader('Content-Security-Policy', "default-src 'none'");
        });

        $response = (new ContentSecurityPolicyMiddleware())->process(new ServerRequest(), $handler);

        $this->assertSame([
            "default-src 'none'; form-action 'self' https://login.example.test; frame-ancestors 'none'",
        ], $response->getHeader('Content-Security-Policy'));
    }

    private function defaultCsp(): string
    {
        return "default-src 'none';"
            . ' ' . "script-src 'self';"
            . ' ' . "style-src 'self';"
            . ' ' . "img-src 'self';"
            . ' ' . "font-src 'self';"
            . ' ' . "connect-src 'self';"
            . ' ' . "base-uri 'self';"
            . ' ' . "frame-src 'self';"
            . ' ' . "frame-ancestors 'none';"
            . ' ' . "form-action 'self' https://*.duosecurity.com";
    }
}
