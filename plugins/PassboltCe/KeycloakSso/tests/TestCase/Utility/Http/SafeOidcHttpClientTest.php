<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Utility\Http;

use Cake\Http\Client;
use Cake\Http\Client\AdapterInterface;
use Cake\Http\Client\Response;
use Cake\TestSuite\TestCase;
use Passbolt\KeycloakSso\Error\Exception\OidcNetworkException;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;
use Passbolt\KeycloakSso\Test\Utility\StaticHostResolver;
use Passbolt\KeycloakSso\Utility\Http\SafeOidcHttpClient;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Http\Message\RequestInterface;

final class SafeOidcHttpClientTest extends TestCase
{
    public function testAcceptsExactOriginResolvingToPublicAddress(): void
    {
        $client = new SafeOidcHttpClient($this->configuration(), null, new StaticHostResolver(['203.0.113.10']));

        $client->assertSafeUrl('https://keyclock.gobaz.ir/realms/passbolt/protocol/openid-connect/certs');
        $this->assertTrue(true);
    }

    public function testRejectsHttpEndpoint(): void
    {
        $client = new SafeOidcHttpClient($this->configuration(), null, new StaticHostResolver(['203.0.113.10']));

        $this->expectException(OidcNetworkException::class);
        $client->assertSafeUrl('http://keyclock.gobaz.ir/realms/passbolt');
    }

    public function testRejectsUnexpectedOrigin(): void
    {
        $client = new SafeOidcHttpClient($this->configuration(), null, new StaticHostResolver(['203.0.113.10']));

        $this->expectException(OidcNetworkException::class);
        $client->assertSafeUrl('https://evil.example/jwks');
    }

    public function testRejectsRedirectResponse(): void
    {
        $response = $this->createMock(Response::class);
        $response->method('getStatusCode')->willReturn(302);
        $cakeClient = $this->createMock(Client::class);
        $cakeClient->method('get')->willReturn($response);
        $client = new SafeOidcHttpClient(
            $this->configuration(),
            $cakeClient,
            new StaticHostResolver(['203.0.113.10'])
        );

        $this->expectException(OidcNetworkException::class);
        $client->requestJson('GET', 'https://keyclock.gobaz.ir/realms/passbolt/.well-known/openid-configuration');
    }

    public function testRejectsOversizedResponse(): void
    {
        $response = $this->createMock(Response::class);
        $response->method('getStatusCode')->willReturn(200);
        $response->method('getHeaderLine')->willReturn((string)(OidcConfigurationDto::MAX_HTTP_RESPONSE_BYTES + 1));
        $cakeClient = $this->createMock(Client::class);
        $cakeClient->method('get')->willReturn($response);
        $client = new SafeOidcHttpClient(
            $this->configuration(),
            $cakeClient,
            new StaticHostResolver(['203.0.113.10'])
        );

        $this->expectException(OidcNetworkException::class);
        $client->requestJson('GET', 'https://keyclock.gobaz.ir/realms/passbolt/.well-known/openid-configuration');
    }

    public function testPinsValidatedDnsAddressAndLimitsTransfer(): void
    {
        $url = 'https://keyclock.gobaz.ir/realms/passbolt/.well-known/openid-configuration';
        $response = $this->createMock(Response::class);
        $response->method('getStatusCode')->willReturn(200);
        $response->method('getHeaderLine')->willReturn('2');
        $response->method('getStringBody')->willReturn('{}');
        $cakeClient = $this->createMock(Client::class);
        $cakeClient->expects($this->once())
            ->method('get')
            ->with($url, [], $this->callback(static function (array $options): bool {
                $curl = $options['curl'] ?? [];

                return ($curl[CURLOPT_RESOLVE][0] ?? null) === 'keyclock.gobaz.ir:443:203.0.113.10' &&
                    ($curl[CURLOPT_MAXFILESIZE] ?? null) === OidcConfigurationDto::MAX_HTTP_RESPONSE_BYTES &&
                    isset($curl[CURLOPT_XFERINFOFUNCTION]);
            }))
            ->willReturn($response);
        $client = new SafeOidcHttpClient(
            $this->configuration(),
            $cakeClient,
            new StaticHostResolver(['203.0.113.10'])
        );

        $this->assertSame([], $client->requestJson('GET', $url));
    }

    public function testPostFormUsesCakeUrlEncodingWithoutInvalidTypeAlias(): void
    {
        $url = 'https://keyclock.gobaz.ir/realms/passbolt/protocol/openid-connect/token';
        $form = [
            'grant_type' => 'authorization_code',
            'code' => 'dummy-authorization-code',
            'redirect_uri' => 'https://passbolt.gobaz.ir/auth/keycloak/callback',
            'client_id' => 'passbolt',
            'client_secret' => 'dummy-client-secret',
            'code_verifier' => 'dummy-pkce-verifier',
        ];
        $adapter = new class implements AdapterInterface {
            public ?RequestInterface $request = null;

            /**
             * @var array<string, mixed>
             */
            public array $options = [];

            public function send(RequestInterface $request, array $options): array
            {
                $this->request = $request;
                $this->options = $options;

                return [new Response(['HTTP/1.1 200 OK', 'Content-Length: 2'], '{}')];
            }
        };
        $client = new SafeOidcHttpClient(
            $this->configuration(),
            new Client(['adapter' => $adapter]),
            new StaticHostResolver(['203.0.113.10'])
        );

        $this->assertSame([], $client->requestJson('POST', $url, $form));
        $this->assertNotNull($adapter->request);
        $this->assertArrayNotHasKey('type', $adapter->options);
        $this->assertSame('application/x-www-form-urlencoded', $adapter->request->getHeaderLine('Content-Type'));
        parse_str((string)$adapter->request->getBody(), $sentForm);
        $this->assertSame($form, $sentForm);
    }

    #[DataProvider('unsafeAddressProvider')]
    public function testRejectsUnsafeDestination(string $address): void
    {
        $client = new SafeOidcHttpClient($this->configuration(), null, new StaticHostResolver([$address]));

        $this->expectException(OidcNetworkException::class);
        $client->assertSafeUrl('https://keyclock.gobaz.ir/realms/passbolt');
    }

    public static function unsafeAddressProvider(): array
    {
        return [
            'IPv4 loopback' => ['127.0.0.1'],
            'IPv4 private' => ['10.0.0.1'],
            'IPv4 link local' => ['169.254.1.1'],
            'IPv6 loopback' => ['::1'],
            'IPv6 unique local' => ['fd00::1'],
            'IPv6 link local' => ['fe80::1'],
        ];
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
}
