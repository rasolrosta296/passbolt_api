<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Configuration;

use Cake\Core\Configure;
use Passbolt\KeycloakSso\Configuration\CryptoConfigurationService;
use Passbolt\KeycloakSso\Error\Exception\OidcConfigurationException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class CryptoConfigurationServiceTest extends TestCase
{
    private mixed $previousOrigin;

    protected function setUp(): void
    {
        parent::setUp();
        $this->previousOrigin = Configure::read('App.fullBaseUrl');
        Configure::write('App.fullBaseUrl', 'https://passbolt.example.test');
    }

    protected function tearDown(): void
    {
        Configure::write('App.fullBaseUrl', $this->previousOrigin);
        parent::tearDown();
    }

    public function testLoadsStrictKeyRingAndFreshnessPolicy(): void
    {
        $key = random_bytes(32);
        $configuration = (new CryptoConfigurationService())->load([
            CryptoConfigurationService::RELEASE_ACR => 'urn:keycloak:acr:mfa',
            CryptoConfigurationService::RELEASE_AMR => '["pwd","otp"]',
            CryptoConfigurationService::ACTIVE_KEK_ID => 'kek-2026-09',
            CryptoConfigurationService::KEK_KEYRING => json_encode([
                'kek-2026-09' => base64_encode($key),
            ], JSON_THROW_ON_ERROR),
        ]);

        $this->assertSame('https://passbolt.example.test', $configuration->passboltOrigin);
        $this->assertSame('urn:keycloak:acr:mfa', $configuration->requiredAcr);
        $this->assertSame(['pwd', 'otp'], $configuration->requiredAmrValues);
        $this->assertSame($key, $configuration->serverShareKeys['kek-2026-09']);
    }

    #[DataProvider('invalidConfigurationProvider')]
    public function testRejectsInvalidConfiguration(array $overrides): void
    {
        $environment = [
            CryptoConfigurationService::RELEASE_ACR => 'urn:keycloak:acr:mfa',
            CryptoConfigurationService::RELEASE_AMR => '',
            CryptoConfigurationService::ACTIVE_KEK_ID => 'active',
            CryptoConfigurationService::KEK_KEYRING => json_encode([
                'active' => base64_encode(random_bytes(32)),
            ], JSON_THROW_ON_ERROR),
        ];
        $this->expectException(OidcConfigurationException::class);
        (new CryptoConfigurationService())->load(array_replace($environment, $overrides));
    }

    public static function invalidConfigurationProvider(): array
    {
        return [
            'missing acr' => [[CryptoConfigurationService::RELEASE_ACR => false]],
            'missing active key' => [[CryptoConfigurationService::ACTIVE_KEK_ID => 'absent']],
            'uppercase active key id' => [[CryptoConfigurationService::ACTIVE_KEK_ID => 'Active']],
            'uppercase keyring key id' => [[CryptoConfigurationService::KEK_KEYRING => json_encode([
                'Active' => base64_encode(random_bytes(32)),
            ], JSON_THROW_ON_ERROR)]],
            'short key' => [[CryptoConfigurationService::KEK_KEYRING => '{"active":"YQ=="}']],
            'invalid amr' => [[CryptoConfigurationService::RELEASE_AMR => '["pwd",1]']],
            'duplicate amr' => [[CryptoConfigurationService::RELEASE_AMR => '["pwd","pwd"]']],
        ];
    }

    #[DataProvider('invalidOriginProvider')]
    public function testRejectsNonCanonicalOrUnsafeOrigin(string $origin): void
    {
        Configure::write('App.fullBaseUrl', $origin);
        $this->expectException(OidcConfigurationException::class);
        (new CryptoConfigurationService())->load([
            CryptoConfigurationService::RELEASE_ACR => 'urn:keycloak:acr:mfa',
            CryptoConfigurationService::ACTIVE_KEK_ID => 'active',
            CryptoConfigurationService::KEK_KEYRING => json_encode([
                'active' => base64_encode(random_bytes(32)),
            ], JSON_THROW_ON_ERROR),
        ]);
    }

    public static function invalidOriginProvider(): array
    {
        return [
            'http' => ['http://passbolt.example.test'],
            'path' => ['https://passbolt.example.test/app'],
            'upper case' => ['https://PASSBOLT.example.test'],
            'default port' => ['https://passbolt.example.test:443'],
            'single label' => ['https://passbolt'],
        ];
    }
}
