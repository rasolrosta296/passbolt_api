<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Controller;

use App\Model\Entity\AuthenticationToken;
use App\Model\Entity\User;
use App\Test\Factory\AuthenticationTokenFactory;
use App\Test\Factory\UserFactory;
use Passbolt\KeycloakSso\Configuration\KeycloakSsoEnvironment;
use Passbolt\KeycloakSso\Configuration\OidcConfigurationService;
use Passbolt\KeycloakSso\Model\Dto\AccountRecoveryConfigurationDto;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;
use Passbolt\KeycloakSso\Model\Dto\PendingIdentityLink;
use Passbolt\KeycloakSso\Model\Dto\ValidatedOidcIdentity;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction;
use Passbolt\KeycloakSso\Service\Identity\IdentityLinkPersistenceService;
use Passbolt\KeycloakSso\Service\Oidc\OidcCookieService;
use Passbolt\KeycloakSso\Service\Oidc\OidcMetadataCache;
use Passbolt\KeycloakSso\Service\Recovery\AccountRecoveryIdentityProofProtector;
use Passbolt\KeycloakSso\Service\Recovery\AccountRecoveryOidcProofService;
use Passbolt\KeycloakSso\Service\Transaction\ClaimOidcTransactionService;
use Passbolt\KeycloakSso\Service\Transaction\CreateOidcTransactionService;
use Passbolt\KeycloakSso\Service\Transaction\TransactionSecretProtector;
use Passbolt\KeycloakSso\Test\Lib\KeycloakSsoIntegrationTestCase;

final class AccountRecoveryControllerTest extends KeycloakSsoIntegrationTestCase
{
    private const ISSUER = 'https://keyclock.gobaz.ir/realms/passbolt';
    /**
     * @var array<string, string|false>
     */
    private array $previousEnvironment = [];

    public function setUp(): void
    {
        foreach ($this->environment() as $name => $value) {
            $this->previousEnvironment[$name] = getenv($name);
            putenv($name . '=' . $value);
        }
        parent::setUp();
    }

    public function tearDown(): void
    {
        foreach ($this->previousEnvironment as $name => $value) {
            putenv($value === false ? $name : $name . '=' . $value);
        }
        parent::tearDown();
    }

    public function testGuestCanStartOnlyFreshInteractiveConfiguredRecoveryFlow(): void
    {
        $this->cacheDiscoveryDocument();

        $this->get('/auth/keycloak/recover?issuer=https://attacker.example');
        $this->assertResponseOk();
        $this->assertResponseContains('Your Passbolt recovery kit and passphrase are still required.');
        $this->assertSame('no-store', $this->_response->getHeaderLine('Cache-Control'));
        $csp = $this->_response->getHeaderLine('Content-Security-Policy');
        $this->assertStringContainsString('https://keyclock.gobaz.ir', $csp);
        $this->assertStringNotContainsString('/realms/passbolt', $csp);
        $this->assertStringNotContainsString('attacker.example', $csp);

        $this->post('/auth/keycloak/recover/start?issuer=https://attacker.example', []);
        $this->assertResponseCode(303);
        $location = $this->_response->getHeaderLine('Location');
        $startCsp = $this->_response->getHeaderLine('Content-Security-Policy');
        $this->assertStringContainsString('https://keyclock.gobaz.ir', $startCsp);
        $this->assertStringNotContainsString('/realms/passbolt', $startCsp);
        $this->assertStringNotContainsString('attacker.example', $startCsp);
        $this->assertStringStartsWith(
            self::ISSUER . '/protocol/openid-connect/auth?',
            $location
        );
        parse_str((string)parse_url($location, PHP_URL_QUERY), $query);
        $this->assertSame('login', $query['prompt']);
        $this->assertSame('0', $query['max_age']);
        $this->assertSame('S256', $query['code_challenge_method']);
        $claims = json_decode($query['claims'], true, 8, JSON_THROW_ON_ERROR);
        $this->assertSame([
            'essential' => true,
            'value' => 'urn:keycloak:acr:mfa',
        ], $claims['id_token']['acr']);
        $this->assertStringNotContainsString('attacker.example', $location);
    }

    public function testAnonymousSettingsExposeOnlyBooleanAvailability(): void
    {
        $this->getJson('/settings.json');

        $this->assertSuccess();
        $settings = $this->_responseJsonBody->passbolt->plugins->keycloakSso;
        $this->assertTrue($settings->enabled);
        $this->assertTrue($settings->accountRecoveryEnabled);
        $serialized = json_encode($settings, JSON_THROW_ON_ERROR);
        $this->assertStringNotContainsString('urn:keycloak:acr:mfa', $serialized);
        $this->assertStringNotContainsString('client-secret-for-tests', $serialized);
    }

    public function testRecoveryProofCreatesNoSessionAndOnlyConsumptionMintsCoreRecoveryToken(): void
    {
        $user = $this->activeLinkedUser();
        $result = $this->successfulResult($user);
        $before = AuthenticationTokenFactory::count();

        $this->getJson('/auth/is-authenticated.json');
        $this->assertAuthenticationError();
        $this->assertSame($before, AuthenticationTokenFactory::count());

        $this->cookie(OidcCookieService::ACCOUNT_RECOVERY_RESULT_COOKIE, $result);
        $this->get('/auth/keycloak/recover/complete');

        $this->assertResponseCode(303);
        $token = AuthenticationTokenFactory::find()->where([
            'user_id' => $user->id,
            'type' => AuthenticationToken::TYPE_RECOVER,
            'active' => true,
        ])->firstOrFail();
        $this->assertInstanceOf(AuthenticationToken::class, $token);
        $this->assertRedirect('/setup/recover/start/' . $user->id . '/' . $token->token);
        $this->assertCookieExpired(OidcCookieService::ACCOUNT_RECOVERY_RESULT_COOKIE);
        $this->assertSame('no-store', $this->_response->getHeaderLine('Cache-Control'));
        $this->assertEmpty($this->getSession()->read('Auth.user'));

        $this->getJson('/auth/is-authenticated.json');
        $this->assertAuthenticationError();
        $this->assertEmpty($this->getSession()->read('Auth.user'));

        $this->cookie(OidcCookieService::ACCOUNT_RECOVERY_RESULT_COOKIE, $result);
        $this->get('/auth/keycloak/recover/complete');
        $this->assertResponseCode(303);
        $this->assertRedirect('/auth/keycloak/recover/error');
        $this->assertSame($before + 1, AuthenticationTokenFactory::count());
    }

    public function testAuthenticatedUserCannotStartOrConsumeGuestRecovery(): void
    {
        $user = $this->activeLinkedUser();
        $this->logInAs($user);

        $this->get('/auth/keycloak/recover');
        $this->assertResponseCode(403);

        $this->post('/auth/keycloak/recover/start', []);
        $this->assertResponseCode(403);

        $before = AuthenticationTokenFactory::count();
        $this->cookie(OidcCookieService::ACCOUNT_RECOVERY_RESULT_COOKIE, str_repeat('r', 43));
        $this->get('/auth/keycloak/recover/complete');
        $this->assertResponseCode(403);
        $this->assertSame($before, AuthenticationTokenFactory::count());
    }

    public function testFailurePageIsGenericNonCacheableAndExpiresResultCookie(): void
    {
        $sensitive = 'sensitive-provider-detail';
        $this->cookie(OidcCookieService::ACCOUNT_RECOVERY_RESULT_COOKIE, str_repeat('r', 43));

        $this->get('/auth/keycloak/recover/error?error_description=' . $sensitive);

        $this->assertResponseOk();
        $this->assertResponseContains('This browser could not be authorized for Passbolt account recovery.');
        $this->assertResponseNotContains($sensitive);
        $this->assertCookieExpired(OidcCookieService::ACCOUNT_RECOVERY_RESULT_COOKIE);
        $this->assertSame('no-store', $this->_response->getHeaderLine('Cache-Control'));
        $this->assertSame('no-cache', $this->_response->getHeaderLine('Pragma'));
        $this->assertStringNotContainsString(
            'https://keyclock.gobaz.ir',
            $this->_response->getHeaderLine('Content-Security-Policy')
        );
        $this->assertEmpty($this->getSession()->read('Auth.user'));
    }

    public function testIndependentDisabledGateFailsClosed(): void
    {
        putenv(KeycloakSsoEnvironment::ACCOUNT_RECOVERY_ENABLED . '=false');

        $this->get('/auth/keycloak/recover');

        $this->assertResponseCode(404);
    }

    private function activeLinkedUser(): User
    {
        $user = UserFactory::make(['username' => 'linked@example.com'])
            ->user()->active()->notDisabled()->persist();
        $this->assertInstanceOf(User::class, $user);
        (new IdentityLinkPersistenceService())->create(
            $user->id,
            new PendingIdentityLink(self::ISSUER, 'immutable-subject', $user->username)
        );

        return $user;
    }

    private function successfulResult(User $user): string
    {
        $oidc = (new OidcConfigurationService())->load();
        $protector = new TransactionSecretProtector($oidc->transactionEncryptionKey);
        $created = (new CreateOidcTransactionService($protector))->create(
            $oidc->issuer,
            $oidc->clientId,
            $oidc->redirectUri,
            $oidc->configurationHash(),
            OidcConfigurationDto::TRANSACTION_TTL_SECONDS,
            KeycloakSsoTransaction::PURPOSE_ACCOUNT_RECOVERY
        );
        $claims = new ClaimOidcTransactionService($protector);
        $transaction = $claims->claim(
            $created->state,
            $created->browserBinding,
            $oidc->configurationHash()
        )['transaction'];
        (new AccountRecoveryOidcProofService(
            new AccountRecoveryIdentityProofProtector($protector),
            new AccountRecoveryConfigurationDto('urn:keycloak:acr:mfa', ['otp'])
        ))->verify($transaction, new ValidatedOidcIdentity(
            'immutable-subject',
            $user->username,
            time(),
            'urn:keycloak:acr:mfa',
            ['otp']
        ));

        return $claims->succeed($transaction->id, OidcConfigurationDto::ACCOUNT_RECOVERY_RESULT_TTL_SECONDS);
    }

    private function cacheDiscoveryDocument(): void
    {
        $configuration = (new OidcConfigurationService())->load();
        (new OidcMetadataCache())->write('discovery', $configuration->configurationHash(), [
            'issuer' => self::ISSUER,
            'authorization_endpoint' => self::ISSUER . '/protocol/openid-connect/auth',
            'token_endpoint' => self::ISSUER . '/protocol/openid-connect/token',
            'jwks_uri' => self::ISSUER . '/protocol/openid-connect/certs',
            'response_types_supported' => ['code'],
            'scopes_supported' => ['openid', 'email'],
            'id_token_signing_alg_values_supported' => ['RS256'],
            'code_challenge_methods_supported' => ['S256'],
        ]);
    }

    /** @return array<string, string> */
    private function environment(): array
    {
        return [
            KeycloakSsoEnvironment::ISSUER => self::ISSUER,
            KeycloakSsoEnvironment::CLIENT_ID => 'passbolt',
            KeycloakSsoEnvironment::CLIENT_SECRET => 'client-secret-for-tests',
            KeycloakSsoEnvironment::REDIRECT_URI => 'https://passbolt.gobaz.ir/auth/keycloak/callback',
            KeycloakSsoEnvironment::TRANSACTION_ENCRYPTION_KEY => base64_encode(str_repeat('K', 32)),
            KeycloakSsoEnvironment::ACCOUNT_RECOVERY_ENABLED => 'true',
            KeycloakSsoEnvironment::ACCOUNT_RECOVERY_ACR => 'urn:keycloak:acr:mfa',
            KeycloakSsoEnvironment::ACCOUNT_RECOVERY_AMR => '["otp"]',
        ];
    }
}
