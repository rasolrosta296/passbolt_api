<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Service\Http;

use App\Middleware\ContentSecurityPolicyExtension;
use App\Middleware\ContentSecurityPolicyMiddleware;
use Cake\Http\Exception\InternalErrorException;
use Cake\Http\ServerRequest;
use Cake\TestSuite\TestCase;
use Passbolt\KeycloakSso\Configuration\KeycloakSsoEnvironment;
use Passbolt\KeycloakSso\Error\Exception\OidcConfigurationException;
use Passbolt\KeycloakSso\Service\Http\ConfiguredIssuerFormActionService;

final class ConfiguredIssuerFormActionServiceTest extends TestCase
{
    /**
     * @var array<string, string|false>
     */
    private array $previousEnvironment = [];

    public function setUp(): void
    {
        $environment = [
            KeycloakSsoEnvironment::ENABLED => 'true',
            KeycloakSsoEnvironment::ISSUER => 'https://keyclock.gobaz.ir/realms/passbolt',
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

    public function testRejectsNonHttpsIssuerWithoutAddingFormActionSource(): void
    {
        putenv(KeycloakSsoEnvironment::ISSUER . '=http://keyclock.gobaz.ir/realms/passbolt');
        $extension = new ContentSecurityPolicyExtension();
        $request = (new ServerRequest())->withAttribute(
            ContentSecurityPolicyMiddleware::EXTENSION_ATTRIBUTE,
            $extension
        );

        $this->expectException(OidcConfigurationException::class);
        try {
            (new ConfiguredIssuerFormActionService())->allow($request);
        } finally {
            $this->assertSame([], $extension->formActionOrigins());
        }
    }

    public function testFailsClosedWithoutRequestScopedExtension(): void
    {
        $this->expectException(InternalErrorException::class);

        (new ConfiguredIssuerFormActionService())->allow(new ServerRequest());
    }
}
