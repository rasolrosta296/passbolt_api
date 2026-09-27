<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Service\Audit;

use Cake\Log\Engine\ArrayLog;
use Cake\Log\Log;
use Cake\TestSuite\TestCase;
use Passbolt\KeycloakSso\Service\Audit\ProvisioningAuditService;

final class ProvisioningAuditServiceTest extends TestCase
{
    private const LOGGER = 'keycloak_sso_provisioning_security_test';

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

    public function testLogsOnlyAllowlistedMetadataAndNeverCallerSuppliedSecrets(): void
    {
        $sensitiveValues = [
            'service-account-token',
            'provisioning-client-secret',
            'raw-keycloak-subject',
            'new.user@example.test',
            'administrator-event-id',
        ];
        $audit = new ProvisioningAuditService();
        $audit->record(implode('-', $sensitiveValues), implode('-', $sensitiveValues), implode('-', $sensitiveValues));

        $engine = Log::engine(self::LOGGER);
        $this->assertInstanceOf(ArrayLog::class, $engine);
        $output = implode("\n", $engine->read());
        foreach ($sensitiveValues as $value) {
            $this->assertStringNotContainsString($value, $output);
        }
        $this->assertStringContainsString('event=failed', $output);
        $this->assertStringContainsString('category=unexpected', $output);
        $this->assertStringContainsString('user=none', $output);
    }
}
