<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Service\Provisioning;

use Passbolt\KeycloakSso\Error\Exception\ProvisioningException;
use Passbolt\KeycloakSso\Model\Dto\OidcDiscoveryDocument;
use Passbolt\KeycloakSso\Model\Dto\ProvisioningConfigurationDto;
use Passbolt\KeycloakSso\Service\Provisioning\KeycloakProvisioningApiService;
use Passbolt\KeycloakSso\Test\Utility\QueuedOidcHttpClient;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class KeycloakProvisioningApiServiceTest extends TestCase
{
    public function testUsesClientCredentialsAndBearerTokenForStrictEventQuery(): void
    {
        $http = new QueuedOidcHttpClient([
            ['access_token' => 'service-token', 'token_type' => 'Bearer'],
            [[
                'id' => '7cd5488d-b1ec-42f6-925d-795620ff2701',
                'time' => 1_789_569_606_000,
                'operationType' => 'CREATE',
                'resourceType' => 'USER',
                'resourcePath' => 'users/e2bc1228-043a-4512-8a91-f08683e55e53',
            ]],
        ]);
        $page = $this->service($http)->events(1_789_569_000_000, 0);

        $this->assertSame(1, $page->received);
        $this->assertCount(1, $page->events);
        $this->assertSame('e2bc1228-043a-4512-8a91-f08683e55e53', $page->events[0]->subject);
        $this->assertSame('POST', $http->requests[0]['method']);
        $this->assertSame([
            'grant_type' => 'client_credentials',
            'client_id' => 'passbolt-provisioning',
            'client_secret' => 'provisioning-secret',
        ], $http->requests[0]['form']);
        $this->assertSame('Bearer service-token', $http->requests[1]['headers']['Authorization']);
        $this->assertStringContainsString('operationTypes=CREATE&operationTypes=UPDATE', $http->requests[1]['url']);
        $this->assertStringContainsString('resourceTypes=USER', $http->requests[1]['url']);
        $this->assertStringNotContainsString('service-token', $http->requests[1]['url']);
    }

    public function testFetchesCurrentUserAndReusesInMemoryToken(): void
    {
        $http = new QueuedOidcHttpClient([
            ['access_token' => 'service-token', 'token_type' => 'bearer'],
            [],
            [
                'id' => 'e2bc1228-043a-4512-8a91-f08683e55e53',
                'email' => 'user@example.test',
                'emailVerified' => true,
                'enabled' => true,
                'firstName' => 'Example',
                'lastName' => 'User',
            ],
        ]);
        $service = $this->service($http);
        $service->events(1_789_569_000_000, 0);
        $user = $service->user('e2bc1228-043a-4512-8a91-f08683e55e53');

        $this->assertSame('user@example.test', $user->email);
        $this->assertTrue($user->emailVerified);
        $this->assertTrue($user->enabled);
        $this->assertCount(3, $http->requests);
        $this->assertSame('GET', $http->requests[2]['method']);
    }

    public function testExcludesFailedAndNestedEventsButPreservesRawPageSize(): void
    {
        $valid = [
            'id' => '7cd5488d-b1ec-42f6-925d-795620ff2701',
            'time' => 1_789_569_606_000,
            'operationType' => 'CREATE',
            'resourceType' => 'USER',
            'resourcePath' => 'users/e2bc1228-043a-4512-8a91-f08683e55e53',
        ];
        $failed = array_replace($valid, [
            'id' => '8d020e76-4951-58d2-b68e-99e2fc1053f8',
            'resourcePath' => 'users',
            'error' => 'user_exists',
        ]);
        $nested = array_replace($valid, [
            'id' => '4d2d5c43-a76a-5d4a-8f47-2b1f0268e3d6',
            'operationType' => 'UPDATE',
            'resourcePath' => 'users/e2bc1228-043a-4512-8a91-f08683e55e53/reset-password',
        ]);
        $http = new QueuedOidcHttpClient([
            ['access_token' => 'service-token', 'token_type' => 'Bearer'],
            [$failed, $nested, $valid],
        ]);

        $page = $this->service($http)->events(0, 0);

        $this->assertSame(3, $page->received);
        $this->assertCount(1, $page->events);
        $this->assertSame($valid['id'], $page->events[0]->eventId);
    }

    #[DataProvider('invalidEventProvider')]
    public function testFailsClosedOnMalformedOrUnrelatedEvent(array $event): void
    {
        $http = new QueuedOidcHttpClient([
            ['access_token' => 'service-token', 'token_type' => 'Bearer'],
            [$event],
        ]);

        $this->expectException(ProvisioningException::class);
        $this->service($http)->events(0, 0);
    }

    public static function invalidEventProvider(): array
    {
        $valid = [
            'id' => '7cd5488d-b1ec-42f6-925d-795620ff2701',
            'time' => 1_789_569_606_000,
            'operationType' => 'CREATE',
            'resourceType' => 'USER',
            'resourcePath' => 'users/e2bc1228-043a-4512-8a91-f08683e55e53',
        ];

        return [
            'missing id' => [array_diff_key($valid, ['id' => true])],
            'wrong time type' => [array_replace($valid, ['time' => '1789569606000'])],
            'delete' => [array_replace($valid, ['operationType' => 'DELETE'])],
            'client event' => [array_replace($valid, ['resourceType' => 'CLIENT'])],
            'foreign resource path' => [array_replace($valid, ['resourcePath' => 'clients/id'])],
            'control in subject' => [array_replace($valid, ['resourcePath' => "users/id\nother"])],
            'malformed error' => [array_replace($valid, ['error' => "failure\nvalue"])],
        ];
    }

    public function testRejectsMismatchedUserSubject(): void
    {
        $http = new QueuedOidcHttpClient([
            ['access_token' => 'service-token', 'token_type' => 'Bearer'],
            [
                'id' => 'another-subject',
                'email' => 'user@example.test',
                'emailVerified' => true,
                'enabled' => true,
                'firstName' => 'Example',
                'lastName' => 'User',
            ],
        ]);

        $this->expectException(ProvisioningException::class);
        $this->service($http)->user('e2bc1228-043a-4512-8a91-f08683e55e53');
    }

    #[DataProvider('invalidTokenProvider')]
    public function testRejectsInvalidServiceAccountTokenResponse(array $response): void
    {
        $http = new QueuedOidcHttpClient([$response]);

        $this->expectException(ProvisioningException::class);
        $this->service($http)->events(0, 0);
    }

    public static function invalidTokenProvider(): array
    {
        return [
            'missing token' => [['token_type' => 'Bearer']],
            'wrong token type' => [['access_token' => 'token', 'token_type' => 'DPoP']],
            'control' => [['access_token' => "token\nvalue", 'token_type' => 'Bearer']],
        ];
    }

    private function service(QueuedOidcHttpClient $http): KeycloakProvisioningApiService
    {
        return new KeycloakProvisioningApiService(
            new ProvisioningConfigurationDto(
                'https://keyclock.gobaz.ir/realms/passbolt',
                'https://keyclock.gobaz.ir/admin/realms/passbolt',
                'passbolt-provisioning',
                'provisioning-secret',
                '8d020e76-4951-58d2-b68e-99e2fc1053f8',
                86_400,
                300,
                100
            ),
            new OidcDiscoveryDocument(
                'https://keyclock.gobaz.ir/realms/passbolt',
                'https://keyclock.gobaz.ir/realms/passbolt/protocol/openid-connect/auth',
                'https://keyclock.gobaz.ir/realms/passbolt/protocol/openid-connect/token',
                'https://keyclock.gobaz.ir/realms/passbolt/protocol/openid-connect/certs'
            ),
            $http
        );
    }
}
