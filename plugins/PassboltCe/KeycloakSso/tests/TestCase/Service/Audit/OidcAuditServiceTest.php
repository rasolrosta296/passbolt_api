<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Service\Audit;

use Cake\Log\Engine\ArrayLog;
use Cake\Log\Log;
use Cake\TestSuite\TestCase;
use Passbolt\KeycloakSso\Service\Audit\OidcAuditService;

final class OidcAuditServiceTest extends TestCase
{
    private const LOGGER = 'keycloak_sso_security_test';

    protected function setUp(): void
    {
        parent::setUp();
        Log::drop(self::LOGGER);
        Log::setConfig(self::LOGGER, [
            'className' => ArrayLog::class,
            'levels' => ['info', 'warning'],
        ]);
    }

    protected function tearDown(): void
    {
        Log::drop(self::LOGGER);
        parent::tearDown();
    }

    public function testLogsOnlyFixedMessagesAndAllowlistedFailureCategory(): void
    {
        $sensitiveValues = [
            'authorization-code-secret',
            'access-token-secret',
            'refresh-token-secret',
            'id-token-secret',
            'pkce-verifier-secret',
            'raw-state-secret',
            'raw-nonce-secret',
            'client-secret',
            'transaction-key-secret',
            'private-key-secret',
            'passphrase-secret',
        ];
        $audit = new OidcAuditService();
        $audit->success();
        $audit->failure(implode('-', $sensitiveValues));

        $engine = Log::engine(self::LOGGER);
        $this->assertInstanceOf(ArrayLog::class, $engine);
        $output = implode("\n", $engine->read());
        foreach ($sensitiveValues as $value) {
            $this->assertStringNotContainsString($value, $output);
        }
        $this->assertStringContainsString('cryptographic authentication remains required', $output);
        $this->assertStringContainsString('unexpected_failure', $output);
    }
}
