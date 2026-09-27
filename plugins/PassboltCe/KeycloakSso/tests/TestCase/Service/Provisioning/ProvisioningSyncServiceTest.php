<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Service\Provisioning;

use App\Model\Entity\User;
use App\Test\Factory\RoleFactory;
use App\Test\Factory\UserFactory;
use App\Utility\UuidFactory;
use Cake\ORM\TableRegistry;
use Passbolt\KeycloakSso\Model\Dto\OidcDiscoveryDocument;
use Passbolt\KeycloakSso\Model\Dto\ProvisioningConfigurationDto;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoProvisioningEvent;
use Passbolt\KeycloakSso\Service\Audit\ProvisioningAuditService;
use Passbolt\KeycloakSso\Service\Provisioning\KeycloakProvisioningApiService;
use Passbolt\KeycloakSso\Service\Provisioning\ProvisioningSyncService;
use Passbolt\KeycloakSso\Service\Provisioning\ProvisionKeycloakUserService;
use Passbolt\KeycloakSso\Test\Lib\KeycloakSsoIntegrationTestCase;
use Passbolt\KeycloakSso\Test\Utility\QueuedOidcHttpClient;

final class ProvisioningSyncServiceTest extends KeycloakSsoIntegrationTestCase
{
    public function testUsesInitialLookbackAndProvisionsCurrentEligibleUser(): void
    {
        RoleFactory::make()->user()->persist();
        $actor = UserFactory::make()->admin()->active()->notDisabled()->persist();
        $this->assertInstanceOf(User::class, $actor);
        $http = new QueuedOidcHttpClient([
            ['access_token' => 'service-token', 'token_type' => 'Bearer'],
            [$this->eventDocument()],
            $this->userDocument(),
        ]);
        $now = 1_789_570_000_000;

        $counts = $this->service($actor->id, $http)->run(false, $now);

        $this->assertSame(1, $counts[ProvisionKeycloakUserService::OUTCOME_PROVISIONED]);
        $this->assertStringContainsString('dateFrom=' . ($now - 86_400_000), $http->requests[1]['url']);
        $this->assertSame(1, TableRegistry::getTableLocator()->get('Users')->find()->where([
            'username' => 'new.user@example.test',
        ])->count());
    }

    public function testUsesStoredEventTimeWithOverlapAndDeduplicatesReplay(): void
    {
        RoleFactory::make()->user()->persist();
        $actor = UserFactory::make()->admin()->active()->notDisabled()->persist();
        $this->assertInstanceOf(User::class, $actor);
        $event = $this->eventDocument();
        $table = TableRegistry::getTableLocator()->get('Passbolt/KeycloakSso.KeycloakSsoProvisioningEvents');
        $table->saveOrFail($table->newEntity([
            'id' => UuidFactory::uuid(),
            'event_id' => $event['id'],
            'issuer' => 'https://keyclock.gobaz.ir/realms/passbolt',
            'subject' => substr($event['resourcePath'], strlen('users/')),
            'event_time' => $event['time'],
            'operation' => $event['operationType'],
            'status' => KeycloakSsoProvisioningEvent::STATUS_SKIPPED,
            'failure_code' => 'email_unverified',
        ], ['accessibleFields' => ['*' => true]]));
        $http = new QueuedOidcHttpClient([
            ['access_token' => 'service-token', 'token_type' => 'Bearer'],
            [$event],
        ]);

        $counts = $this->service($actor->id, $http)->run();

        $this->assertSame(1, $counts[ProvisionKeycloakUserService::OUTCOME_DUPLICATE]);
        $this->assertStringContainsString(
            'dateFrom=' . ($event['time'] - 300_000),
            $http->requests[1]['url']
        );
        $this->assertCount(2, $http->requests);
    }

    public function testPaginatesWhenRawPageReachesConfiguredBatchSize(): void
    {
        RoleFactory::make()->user()->persist();
        $actor = UserFactory::make()->admin()->active()->notDisabled()->persist();
        $this->assertInstanceOf(User::class, $actor);
        $http = new QueuedOidcHttpClient([
            ['access_token' => 'service-token', 'token_type' => 'Bearer'],
            [$this->eventDocument()],
            $this->userDocument(),
            [],
        ]);

        $this->service($actor->id, $http, 1)->run();

        $this->assertCount(4, $http->requests);
        $this->assertStringContainsString('first=0&max=1', $http->requests[1]['url']);
        $this->assertStringContainsString('first=1&max=1', $http->requests[3]['url']);
    }

    private function service(
        string $actorId,
        QueuedOidcHttpClient $http,
        int $batchSize = 100
    ): ProvisioningSyncService {
        $configuration = new ProvisioningConfigurationDto(
            'https://keyclock.gobaz.ir/realms/passbolt',
            'https://keyclock.gobaz.ir/admin/realms/passbolt',
            'passbolt-provisioning',
            'provisioning-secret',
            $actorId,
            86_400,
            300,
            $batchSize
        );
        $api = new KeycloakProvisioningApiService(
            $configuration,
            new OidcDiscoveryDocument(
                $configuration->issuer,
                $configuration->issuer . '/protocol/openid-connect/auth',
                $configuration->issuer . '/protocol/openid-connect/token',
                $configuration->issuer . '/protocol/openid-connect/certs'
            ),
            $http
        );

        return new ProvisioningSyncService(
            $configuration,
            $api,
            new ProvisionKeycloakUserService($configuration, $api, new ProvisioningAuditService())
        );
    }

    /** @return array<string, mixed> */
    private function eventDocument(): array
    {
        return [
            'id' => '7cd5488d-b1ec-42f6-925d-795620ff2701',
            'time' => 1_789_569_606_000,
            'operationType' => 'CREATE',
            'resourceType' => 'USER',
            'resourcePath' => 'users/e2bc1228-043a-4512-8a91-f08683e55e53',
        ];
    }

    /** @return array<string, mixed> */
    private function userDocument(): array
    {
        return [
            'id' => 'e2bc1228-043a-4512-8a91-f08683e55e53',
            'email' => 'new.user@example.test',
            'emailVerified' => true,
            'enabled' => true,
            'firstName' => 'New',
            'lastName' => 'User',
        ];
    }
}
