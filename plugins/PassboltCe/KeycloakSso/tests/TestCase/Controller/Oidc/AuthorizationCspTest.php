<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Controller\Oidc;

use Cake\Core\Configure;
use Passbolt\KeycloakSso\Configuration\KeycloakSsoEnvironment;
use Passbolt\KeycloakSso\Service\Oidc\OidcServiceFactoryInterface;
use Passbolt\KeycloakSso\Test\Lib\KeycloakSsoIntegrationTestCase;
use Passbolt\KeycloakSso\Test\Utility\RecordingOidcResultConsumer;
use Passbolt\KeycloakSso\Test\Utility\StaticAuthorizationRequestProvider;
use Passbolt\KeycloakSso\Test\Utility\StaticOidcServiceFactory;
use Passbolt\KeycloakSso\Test\Utility\SuccessfulOidcCallbackProcessor;

final class AuthorizationCspTest extends KeycloakSsoIntegrationTestCase
{
    /**
     * @var array<string, string|false>
     */
    private array $previousEnvironment = [];

    public function setUp(): void
    {
        $environment = [
            KeycloakSsoEnvironment::ISSUER => 'https://keyclock.gobaz.ir:443/realms/passbolt',
            KeycloakSsoEnvironment::CLIENT_ID => 'passbolt',
            KeycloakSsoEnvironment::CLIENT_SECRET => 'client-secret-for-tests',
            KeycloakSsoEnvironment::REDIRECT_URI => 'https://passbolt.gobaz.ir/auth/keycloak/callback',
            KeycloakSsoEnvironment::TRANSACTION_ENCRYPTION_KEY => base64_encode(str_repeat('k', 32)),
        ];
        foreach ($environment as $name => $value) {
            $this->previousEnvironment[$name] = getenv($name);
            putenv($name . '=' . $value);
        }

        parent::setUp();
        Configure::write('passbolt.security.csp', null);
    }

    public function tearDown(): void
    {
        parent::tearDown();
        foreach ($this->previousEnvironment as $name => $value) {
            if ($value === false) {
                putenv($name);
            } else {
                putenv($name . '=' . $value);
            }
        }
    }

    public function testAuthorizationPageAllowsOnlyConfiguredIssuerOrigin(): void
    {
        $this->get('/auth/keycloak?issuer=https://attacker.example&redirect_uri=https://attacker.example');

        $this->assertResponseOk();
        $headers = $this->_response->getHeader('Content-Security-Policy');
        $this->assertCount(1, $headers);
        $this->assertStringContainsString(
            "form-action 'self' https://*.duosecurity.com https://keyclock.gobaz.ir",
            $headers[0]
        );
        $this->assertStringNotContainsString('/realms/passbolt', $headers[0]);
        $this->assertStringNotContainsString('attacker.example', $headers[0]);
        $this->assertStringNotContainsString(':443', $headers[0]);
        $this->assertStringContainsString("default-src 'none'; script-src 'self';", $headers[0]);
        $this->assertStringContainsString("frame-ancestors 'none';", $headers[0]);
    }

    public function testAuthorizationStartRedirectUsesSingleExtendedPolicy(): void
    {
        $factory = new StaticOidcServiceFactory(
            new StaticAuthorizationRequestProvider(),
            new SuccessfulOidcCallbackProcessor(),
            new RecordingOidcResultConsumer()
        );
        $this->mockService(OidcServiceFactoryInterface::class, static fn () => $factory);
        $this->enableCsrfToken();

        $this->post('/auth/keycloak/start?issuer=https://attacker.example', []);

        $this->assertResponseCode(303);
        $headers = $this->_response->getHeader('Content-Security-Policy');
        $this->assertCount(1, $headers);
        $this->assertStringContainsString(
            "form-action 'self' https://*.duosecurity.com https://keyclock.gobaz.ir",
            $headers[0]
        );
        $this->assertStringNotContainsString('attacker.example', $headers[0]);
    }
}
