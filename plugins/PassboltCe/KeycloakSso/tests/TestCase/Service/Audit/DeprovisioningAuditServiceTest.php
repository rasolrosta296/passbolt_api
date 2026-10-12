<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Service\Audit;

use Cake\Log\Engine\ArrayLog;
use Cake\Log\Log;
use Cake\TestSuite\TestCase;
use Passbolt\KeycloakSso\Service\Audit\DeprovisioningAuditService;

final class DeprovisioningAuditServiceTest extends TestCase
{
    private const LOGGER = 'keycloak_sso_deprovisioning_security_test';

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

    public function testLogsOnlyAllowlistedMetadata(): void
    {
        $secrets = ['raw-subject', 'user@example.test', 'service-token', 'client-secret'];
        $untrusted = implode('-', $secrets);
        (new DeprovisioningAuditService())->record($untrusted, $untrusted, $untrusted);

        $engine = Log::engine(self::LOGGER);
        $this->assertInstanceOf(ArrayLog::class, $engine);
        $output = implode("\n", $engine->read());
        foreach ($secrets as $secret) {
            $this->assertStringNotContainsString($secret, $output);
        }
        $this->assertStringContainsString('event=failed', $output);
        $this->assertStringContainsString('category=unexpected', $output);
        $this->assertStringContainsString('user=none', $output);
    }

    public function testReactivationUsesOnlyAllowlistedAuditMetadata(): void
    {
        $userId = '8d020e76-4951-58d2-b68e-99e2fc1053f8';
        (new DeprovisioningAuditService())->record('reactivated', 'disabled', $userId);

        $engine = Log::engine(self::LOGGER);
        $this->assertInstanceOf(ArrayLog::class, $engine);
        $output = implode("\n", $engine->read());
        $this->assertStringContainsString('event=reactivated', $output);
        $this->assertStringContainsString('category=disabled', $output);
        $this->assertStringContainsString('user=' . $userId, $output);
    }
}
