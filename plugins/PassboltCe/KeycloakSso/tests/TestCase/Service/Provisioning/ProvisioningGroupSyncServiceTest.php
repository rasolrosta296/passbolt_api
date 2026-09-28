<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Service\Provisioning;

use App\Model\Entity\Group;
use App\Model\Entity\User;
use App\Test\Factory\GroupFactory;
use App\Test\Factory\ResourceFactory;
use App\Test\Factory\UserFactory;
use App\Utility\UuidFactory;
use Cake\ORM\Table;
use Cake\ORM\TableRegistry;
use Passbolt\KeycloakSso\Model\Dto\OidcDiscoveryDocument;
use Passbolt\KeycloakSso\Model\Dto\ProvisioningConfigurationDto;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoGroupMembership;
use Passbolt\KeycloakSso\Service\Provisioning\KeycloakProvisioningApiService;
use Passbolt\KeycloakSso\Service\Provisioning\ProvisioningGroupSyncService;
use Passbolt\KeycloakSso\Test\Lib\KeycloakSsoIntegrationTestCase;
use Passbolt\KeycloakSso\Test\Utility\QueuedOidcHttpClient;

final class ProvisioningGroupSyncServiceTest extends KeycloakSsoIntegrationTestCase
{
    private const ISSUER = 'https://keyclock.gobaz.ir/realms/passbolt';
    private const SUBJECT = 'e2bc1228-043a-4512-8a91-f08683e55e53';

    public function testDryRunCreatesNothing(): void
    {
        [$actor, $user] = $this->users(true);

        $counts = $this->service($actor, $this->responses())->run(true);

        $this->assertSame(1, $counts[ProvisioningGroupSyncService::OUTCOME_GROUP_WOULD_CREATE]);
        $this->assertSame(1, $counts[ProvisioningGroupSyncService::OUTCOME_MEMBERSHIP_WOULD_ADD]);
        $this->assertSame(0, TableRegistry::getTableLocator()->get('Groups')->find()->count());
        $this->assertSame(0, $this->mappedGroups()->find()->count());
        $this->assertSame(0, $this->memberships()->find()->count());
        $this->assertInstanceOf(User::class, $user);
    }

    public function testCreatesGroupAndAddsActiveUserAsNonManager(): void
    {
        [$actor, $user] = $this->users(true);

        $counts = $this->service($actor, $this->responses())->run();

        $this->assertSame(1, $counts[ProvisioningGroupSyncService::OUTCOME_GROUP_CREATED]);
        $this->assertSame(1, $counts[ProvisioningGroupSyncService::OUTCOME_MEMBERSHIP_ADDED]);
        $group = TableRegistry::getTableLocator()->get('Groups')->find()->where(['name' => 'Engineering'])->firstOrFail();
        $this->assertInstanceOf(Group::class, $group);
        $actorMembership = TableRegistry::getTableLocator()->get('GroupsUsers')->find()->where([
            'group_id' => $group->id,
            'user_id' => $actor->id,
        ])->firstOrFail();
        $userMembership = TableRegistry::getTableLocator()->get('GroupsUsers')->find()->where([
            'group_id' => $group->id,
            'user_id' => $user->id,
        ])->firstOrFail();
        $this->assertTrue($actorMembership->get('is_admin'));
        $this->assertFalse($userMembership->get('is_admin'));
        $this->assertSame(1, $this->mappedGroups()->find()->count());
        $state = $this->memberships()->find()->firstOrFail();
        $this->assertSame(KeycloakSsoGroupMembership::STATUS_ACTIVE, $state->get('status'));
    }

    public function testInactiveUserRemainsPendingThenIsAddedAfterActivation(): void
    {
        [$actor, $user] = $this->users(false);

        $first = $this->service($actor, $this->responses())->run();

        $this->assertSame(1, $first[ProvisioningGroupSyncService::OUTCOME_PENDING_ACTIVATION]);
        $this->assertSame(1, TableRegistry::getTableLocator()->get('GroupsUsers')->find()->count());
        $state = $this->memberships()->find()->firstOrFail();
        $this->assertSame(KeycloakSsoGroupMembership::STATUS_PENDING_ACTIVATION, $state->get('status'));

        TableRegistry::getTableLocator()->get('Users')->updateAll(['active' => true], ['id' => $user->id]);
        $second = $this->service($actor, $this->responses())->run();

        $this->assertSame(1, $second[ProvisioningGroupSyncService::OUTCOME_MEMBERSHIP_ADDED]);
        $this->assertSame(2, TableRegistry::getTableLocator()->get('GroupsUsers')->find()->count());
        $this->assertSame(
            KeycloakSsoGroupMembership::STATUS_ACTIVE,
            $this->memberships()->find()->firstOrFail()->get('status')
        );
    }

    public function testGroupWithSharedResourceRemainsPendingForClientCrypto(): void
    {
        [$actor, $user] = $this->users(false);
        $this->service($actor, $this->responses())->run();
        $group = TableRegistry::getTableLocator()->get('Groups')->find()->where(['name' => 'Engineering'])->firstOrFail();
        $this->assertInstanceOf(Group::class, $group);
        ResourceFactory::make()
            ->withSecretRevisions()
            ->withPermissionsFor([$group])
            ->withSecretsFor([$actor])
            ->persist();
        TableRegistry::getTableLocator()->get('Users')->updateAll(['active' => true], ['id' => $user->id]);

        $counts = $this->service($actor, $this->responses())->run();

        $this->assertSame(1, $counts[ProvisioningGroupSyncService::OUTCOME_PENDING_CRYPTO]);
        $this->assertSame(1, TableRegistry::getTableLocator()->get('GroupsUsers')->find()->count());
        $this->assertSame(
            KeycloakSsoGroupMembership::STATUS_PENDING_CRYPTO,
            $this->memberships()->find()->firstOrFail()->get('status')
        );
    }

    public function testDoesNotAdoptPassboltGroupByName(): void
    {
        [$actor] = $this->users(true);
        GroupFactory::make(['name' => 'Engineering'])->withGroupsManagersFor([$actor])->persist();

        $counts = $this->service($actor, $this->responses())->run();

        $this->assertSame(1, $counts[ProvisioningGroupSyncService::OUTCOME_FAILED]);
        $this->assertSame(0, $this->mappedGroups()->find()->count());
        $this->assertSame(1, TableRegistry::getTableLocator()->get('Groups')->find()->count());
    }

    /** @return array{0: User, 1: User} */
    private function users(bool $active): array
    {
        $actor = UserFactory::make()->admin()->active()->notDisabled()->persist();
        $factory = UserFactory::make(['username' => 'new.user@example.test'])->user()->notDisabled();
        $user = ($active ? $factory->active() : $factory->inactive())->persist();
        $this->assertInstanceOf(User::class, $actor);
        $this->assertInstanceOf(User::class, $user);
        $provisioned = $this->provisionedUsers()->newEntity([
            'id' => UuidFactory::uuid(),
            'user_id' => $user->id,
            'issuer' => self::ISSUER,
            'subject' => self::SUBJECT,
            'email_at_provisioning' => 'new.user@example.test',
            'source_event_id' => UuidFactory::uuid(),
        ], ['accessibleFields' => ['*' => true]]);
        $this->provisionedUsers()->saveOrFail($provisioned);

        return [$actor, $user];
    }

    /** @return list<array<mixed>> */
    private function responses(): array
    {
        return [
            ['access_token' => 'service-token', 'token_type' => 'Bearer'],
            [
                'id' => self::SUBJECT,
                'email' => 'new.user@example.test',
                'emailVerified' => true,
                'enabled' => true,
                'firstName' => 'New',
                'lastName' => 'User',
            ],
            [['id' => 'engineering-id', 'name' => 'Engineering', 'path' => '/Engineering']],
        ];
    }

    private function service(User $actor, array $responses): ProvisioningGroupSyncService
    {
        $configuration = new ProvisioningConfigurationDto(
            self::ISSUER,
            'https://keyclock.gobaz.ir/admin/realms/passbolt',
            'passbolt-provisioning',
            'provisioning-secret',
            $actor->id,
            86_400,
            300,
            100
        );
        $api = new KeycloakProvisioningApiService(
            $configuration,
            new OidcDiscoveryDocument(
                self::ISSUER,
                self::ISSUER . '/protocol/openid-connect/auth',
                self::ISSUER . '/protocol/openid-connect/token',
                self::ISSUER . '/protocol/openid-connect/certs'
            ),
            new QueuedOidcHttpClient($responses)
        );

        return new ProvisioningGroupSyncService($configuration, $api);
    }

    private function provisionedUsers(): Table
    {
        return TableRegistry::getTableLocator()->get('Passbolt/KeycloakSso.KeycloakSsoProvisionedUsers');
    }

    private function mappedGroups(): Table
    {
        return TableRegistry::getTableLocator()->get('Passbolt/KeycloakSso.KeycloakSsoProvisionedGroups');
    }

    private function memberships(): Table
    {
        return TableRegistry::getTableLocator()->get('Passbolt/KeycloakSso.KeycloakSsoGroupMemberships');
    }
}
