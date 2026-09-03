<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Service\Audit;

use Cake\Log\Engine\ArrayLog;
use Cake\Log\Log;
use Cake\TestSuite\TestCase;
use Passbolt\KeycloakSso\Service\Audit\IdentityLinkAuditService;

final class IdentityLinkAuditServiceTest extends TestCase
{
    private const LOGGER = 'keycloak_identity_link_security_test';

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

    public function testAuditMessagesExcludeOidcAndCryptographicSecrets(): void
    {
        $sensitiveValues = [
            'authorization-code-secret',
            'access-token-secret',
            'id-token-secret',
            'raw-state-secret',
            'raw-nonce-secret',
            'pkce-verifier-secret',
            'client-secret',
            'subject-secret',
            'email-secret@example.com',
            'private-key-secret',
            'passphrase-secret',
        ];
        $userId = 'f848277c-5398-58f8-a82a-72397af2d450';
        $audit = new IdentityLinkAuditService();
        $audit->linkStarted($userId);
        $audit->linkSucceeded($userId);
        $audit->linkFailed($userId, implode('-', $sensitiveValues));
        $audit->collision($userId);
        $audit->unlinkSucceeded($userId);

        $engine = Log::engine(self::LOGGER);
        $this->assertInstanceOf(ArrayLog::class, $engine);
        $output = implode("\n", $engine->read());
        foreach ($sensitiveValues as $value) {
            $this->assertStringNotContainsString($value, $output);
        }
        $this->assertStringContainsString($userId, $output);
        $this->assertStringContainsString('unexpected_failure', $output);
    }
}
