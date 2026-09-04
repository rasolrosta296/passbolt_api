<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Service\Audit;

use Cake\Log\Engine\ArrayLog;
use Cake\Log\Log;
use Passbolt\KeycloakSso\Service\Audit\CryptoSsoAuditService;
use PHPUnit\Framework\TestCase;

final class CryptoSsoAuditServiceTest extends TestCase
{
    private const LOGGER = 'keycloak_crypto_security_test';

    protected function setUp(): void
    {
        parent::setUp();
        Log::drop(self::LOGGER);
        Log::setConfig(self::LOGGER, [
            'className' => ArrayLog::class,
            'levels' => ['info'],
        ]);
    }

    protected function tearDown(): void
    {
        Log::drop(self::LOGGER);
        parent::tearDown();
    }

    public function testOnlyAllowlistedMetadataCanReachLogs(): void
    {
        (new CryptoSsoAuditService())->record(
            'authorization-code-sensitive',
            'id-token-sensitive',
            'server-share-sensitive'
        );
        $engine = Log::engine(self::LOGGER);
        $this->assertInstanceOf(ArrayLog::class, $engine);
        $output = implode("\n", $engine->read());
        $this->assertStringContainsString('event=release_failed', $output);
        $this->assertStringContainsString('user=anonymous', $output);
        $this->assertStringContainsString('category=unexpected', $output);
        foreach (['authorization-code-sensitive', 'id-token-sensitive', 'server-share-sensitive'] as $secret) {
            $this->assertStringNotContainsString($secret, $output);
        }
    }

    public function testEnrollmentRevocationAuditContainsNoCallerSuppliedSecrets(): void
    {
        $userId = '10000000-0000-4000-8000-000000000001';
        (new CryptoSsoAuditService())->record('enrollment_revoked', $userId, 'revoked');

        $engine = Log::engine(self::LOGGER);
        $this->assertInstanceOf(ArrayLog::class, $engine);
        $output = implode("\n", $engine->read());
        $this->assertStringContainsString('event=enrollment_revoked', $output);
        $this->assertStringContainsString('user=' . $userId, $output);
        $this->assertStringContainsString('category=revoked', $output);
        foreach (['server_share', 'client_enrollment_uuid', 'authorization_code', 'token'] as $secretName) {
            $this->assertStringNotContainsString($secretName, $output);
        }
    }
}
