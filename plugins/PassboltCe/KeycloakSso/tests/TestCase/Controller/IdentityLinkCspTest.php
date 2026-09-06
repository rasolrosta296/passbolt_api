<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Controller;

use App\Model\Entity\User;
use App\Test\Factory\UserFactory;
use Cake\Core\Configure;
use Passbolt\KeycloakSso\Configuration\KeycloakSsoEnvironment;
use Passbolt\KeycloakSso\Configuration\OidcConfigurationService;
use Passbolt\KeycloakSso\Service\Oidc\OidcCookieService;
use Passbolt\KeycloakSso\Service\Oidc\OidcMetadataCache;
use Passbolt\KeycloakSso\Test\Lib\KeycloakSsoIntegrationTestCase;

final class IdentityLinkCspTest extends KeycloakSsoIntegrationTestCase
{
    private const ISSUER_ORIGIN = 'https://keyclock.gobaz.ir';

    /**
     * @var array<string, string|false>
     */
    private array $previousEnvironment = [];

    public function setUp(): void
    {
        $environment = [
            KeycloakSsoEnvironment::ISSUER => self::ISSUER_ORIGIN . ':443/realms/passbolt',
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

    public function testIdentityLinkPageAllowsOnlyConfiguredIssuerOrigin(): void
    {
        $this->logInAs($this->activeUser());

        $this->get('/auth/keycloak/link?issuer=https://attacker.example');

        $this->assertResponseOk();
        $this->assertIssuerAllowed();
    }

    public function testIdentityLinkStartAllowsOnlyConfiguredIssuerOrigin(): void
    {
        $this->cacheDiscoveryDocument();
        $this->logInAs($this->activeUser());

        $this->post('/auth/keycloak/link/start?issuer=https://attacker.example', []);

        $this->assertResponseCode(303);
        $this->assertIssuerAllowed();
    }

    public function testIdentityLinkConfirmationPageDoesNotAllowIssuerOrigin(): void
    {
        $this->logInAs($this->activeUser());
        $this->cookie(OidcCookieService::LINK_RESULT_COOKIE, str_repeat('r', 43));

        $this->get('/auth/keycloak/link/confirm');

        $this->assertResponseOk();
        $this->assertIssuerNotAllowed();
    }

    public function testIdentityLinkConfirmationPostDoesNotAllowIssuerOrigin(): void
    {
        $this->logInAs($this->activeUser());
        $this->cookie(OidcCookieService::LINK_RESULT_COOKIE, str_repeat('r', 43));

        $this->post('/auth/keycloak/link/confirm', ['confirmation' => 'link_keycloak_identity']);

        $this->assertIssuerNotAllowed();
    }

    public function testIdentityUnlinkDoesNotAllowIssuerOrigin(): void
    {
        $this->logInAs($this->activeUser());

        $this->post('/auth/keycloak/unlink', ['confirmation' => 'unlink_keycloak_identity']);

        $this->assertIssuerNotAllowed();
    }

    public function testUnrelatedResponseRetainsDefaultFormAction(): void
    {
        $this->getJson('/auth/is-authenticated.json');

        $this->assertIssuerNotAllowed();
    }

    private function assertIssuerAllowed(): void
    {
        $headers = $this->_response->getHeader('Content-Security-Policy');
        $this->assertCount(1, $headers);
        $this->assertStringContainsString(
            "form-action 'self' https://*.duosecurity.com " . self::ISSUER_ORIGIN,
            $headers[0]
        );
        $this->assertStringNotContainsString('/realms/passbolt', $headers[0]);
        $this->assertStringNotContainsString('attacker.example', $headers[0]);
        $this->assertStringNotContainsString(':443', $headers[0]);
    }

    private function assertIssuerNotAllowed(): void
    {
        $headers = $this->_response->getHeader('Content-Security-Policy');
        $this->assertCount(1, $headers);
        $this->assertStringContainsString("form-action 'self' https://*.duosecurity.com", $headers[0]);
        $this->assertStringNotContainsString(self::ISSUER_ORIGIN, $headers[0]);
    }

    private function activeUser(): User
    {
        $user = UserFactory::make()->user()->active()->notDisabled()->persist();
        self::assertInstanceOf(User::class, $user);

        return $user;
    }

    private function cacheDiscoveryDocument(): void
    {
        $configuration = (new OidcConfigurationService())->load();
        (new OidcMetadataCache())->write('discovery', $configuration->configurationHash(), [
            'issuer' => $configuration->issuer,
            'authorization_endpoint' => self::ISSUER_ORIGIN . '/realms/passbolt/protocol/openid-connect/auth',
            'token_endpoint' => self::ISSUER_ORIGIN . '/realms/passbolt/protocol/openid-connect/token',
            'jwks_uri' => self::ISSUER_ORIGIN . '/realms/passbolt/protocol/openid-connect/certs',
            'response_types_supported' => ['code'],
            'scopes_supported' => ['openid', 'email'],
            'id_token_signing_alg_values_supported' => ['RS256'],
            'code_challenge_methods_supported' => ['S256'],
        ]);
    }
}
