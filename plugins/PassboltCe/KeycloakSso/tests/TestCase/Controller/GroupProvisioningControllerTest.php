<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Controller;

use App\Test\Factory\GroupFactory;
use App\Test\Factory\GroupsUserFactory;
use App\Test\Factory\UserFactory;
use App\Utility\UuidFactory;
use Cake\I18n\DateTime;
use Cake\ORM\TableRegistry;
use Passbolt\KeycloakSso\Configuration\KeycloakSsoEnvironment;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoGroupMembership;
use Passbolt\KeycloakSso\Model\Table\KeycloakSsoGroupMembershipsTable;
use Passbolt\KeycloakSso\Model\Table\KeycloakSsoProvisionedGroupsTable;
use Passbolt\KeycloakSso\Test\Lib\KeycloakSsoIntegrationTestCase;

final class GroupProvisioningControllerTest extends KeycloakSsoIntegrationTestCase
{
    private const ISSUER = 'https://keyclock.gobaz.ir/realms/passbolt';

    private string|false $previousEnabled;

    /**
     * @var array<string, string|false>
     */
    private array $previousOidcEnvironment = [];

    public function setUp(): void
    {
        parent::setUp();
        $this->previousEnabled = getenv(KeycloakSsoEnvironment::GROUP_PROVISIONING_ENABLED);
        putenv(KeycloakSsoEnvironment::GROUP_PROVISIONING_ENABLED . '=true');
        $environment = [
            KeycloakSsoEnvironment::ISSUER => self::ISSUER,
            KeycloakSsoEnvironment::CLIENT_ID => 'test-client',
            KeycloakSsoEnvironment::CLIENT_SECRET => 'test-client-secret',
            KeycloakSsoEnvironment::REDIRECT_URI => 'https://passbolt.example.test/auth/keycloak/callback',
            KeycloakSsoEnvironment::TRANSACTION_ENCRYPTION_KEY => base64_encode(str_repeat('k', 32)),
        ];
        foreach ($environment as $name => $value) {
            $this->previousOidcEnvironment[$name] = getenv($name);
            putenv($name . '=' . $value);
        }
    }

    public function tearDown(): void
    {
        putenv($this->previousEnabled === false
            ? KeycloakSsoEnvironment::GROUP_PROVISIONING_ENABLED
            : KeycloakSsoEnvironment::GROUP_PROVISIONING_ENABLED . '=' . $this->previousEnabled);
        foreach ($this->previousOidcEnvironment as $name => $value) {
            putenv($value === false ? $name : $name . '=' . $value);
        }
        parent::tearDown();
    }

    public function testManagerCanListOnlyOwnPendingCryptographicMemberships(): void
    {
        [$manager, $target, $group, $membership] = $this->pendingMembership();
        $otherManager = UserFactory::make()->user()->active()->notDisabled()->persist();
        $this->logInAs($otherManager);

        $this->getJson('/auth/keycloak/provisioning/groups/pending.json');

        $this->assertSuccess();
        $this->assertSame([], (array)$this->_responseJsonBody->items);

        $this->logInAs($manager);
        $this->getJson('/auth/keycloak/provisioning/groups/pending.json');

        $this->assertSuccess();
        $items = (array)$this->_responseJsonBody->items;
        $this->assertCount(1, $items);
        $this->assertSame($membership->id, $items[0]->id);
        $this->assertSame($group->id, $items[0]->group_id);
        $this->assertSame($target->id, $items[0]->user_id);
        $this->assertSame('no-store', $this->_response->getHeaderLine('Cache-Control'));
        $this->assertSame('no-cache', $this->_response->getHeaderLine('Pragma'));
    }

    public function testCompletionRequiresNormalGroupMembershipThenIsIdempotent(): void
    {
        [$manager, $target, $group, $membership] = $this->pendingMembership();
        $this->logInAs($manager);
        $route = '/auth/keycloak/provisioning/groups/complete/' . $membership->id . '.json';

        $this->postJson($route);
        $this->assertResponseCode(400);
        $this->assertSame(
            KeycloakSsoGroupMembership::STATUS_PENDING_CRYPTO,
            $this->memberships()->get($membership->id)->get('status')
        );

        GroupsUserFactory::make([
            'group_id' => $group->id,
            'user_id' => $target->id,
            'is_admin' => false,
            'created_by' => $manager->id,
            'modified_by' => $manager->id,
        ])->persist();
        $this->postJson($route);

        $this->assertSuccess();
        $this->assertSame(
            KeycloakSsoGroupMembership::STATUS_ACTIVE,
            $this->memberships()->get($membership->id)->get('status')
        );
        $this->postJson($route);
        $this->assertSuccess();
    }

    public function testNonManagerCannotCompletePendingMembership(): void
    {
        [, $target, $group, $membership] = $this->pendingMembership();
        /** @var \App\Model\Entity\User $nonManager */
        $nonManager = UserFactory::make()->user()->active()->notDisabled()->persist();
        GroupsUserFactory::make([
            'group_id' => $group->id,
            'user_id' => $target->id,
            'is_admin' => false,
            'created_by' => $nonManager->id,
            'modified_by' => $nonManager->id,
        ])->persist();
        $this->logInAs($nonManager);

        $this->postJson('/auth/keycloak/provisioning/groups/complete/' . $membership->id . '.json');

        $this->assertResponseCode(403);
        $this->assertSame(
            KeycloakSsoGroupMembership::STATUS_PENDING_CRYPTO,
            $this->memberships()->get($membership->id)->get('status')
        );
    }

    public function testPendingQueueAndCompletionRejectAnotherIssuerNamespace(): void
    {
        [$manager, , , $membership] = $this->pendingMembership('https://keyclock.gobaz.ir/realms/foreign');
        $this->logInAs($manager);

        $this->getJson('/auth/keycloak/provisioning/groups/pending.json');
        $this->assertSuccess();
        $this->assertSame([], (array)$this->_responseJsonBody->items);

        $this->postJson('/auth/keycloak/provisioning/groups/complete/' . $membership->id . '.json');
        $this->assertResponseCode(400);
        $this->assertSame(
            KeycloakSsoGroupMembership::STATUS_PENDING_CRYPTO,
            $this->memberships()->get($membership->id)->get('status')
        );
    }

    public function testDisabledTargetIsHiddenAndCannotBeCompleted(): void
    {
        [$manager, $target, $group, $membership] = $this->pendingMembership();
        GroupsUserFactory::make([
            'group_id' => $group->id,
            'user_id' => $target->id,
            'is_admin' => false,
            'created_by' => $manager->id,
            'modified_by' => $manager->id,
        ])->persist();
        $users = TableRegistry::getTableLocator()->get('Users');
        $users->updateAll(
            ['disabled' => DateTime::yesterday()],
            ['id' => $target->id]
        );
        /** @var \App\Model\Entity\User $disabledTarget */
        $disabledTarget = $users->get($target->id);
        $this->assertTrue($disabledTarget->isDisabled());
        $this->logInAs($manager);

        $this->getJson('/auth/keycloak/provisioning/groups/pending.json');
        $this->assertSuccess();
        $this->assertSame([], (array)$this->_responseJsonBody->items);

        $this->postJson('/auth/keycloak/provisioning/groups/complete/' . $membership->id . '.json');
        $this->assertResponseCode(400);
        $this->assertSame(
            KeycloakSsoGroupMembership::STATUS_PENDING_CRYPTO,
            $this->memberships()->get($membership->id)->get('status')
        );
    }

    public function testQueueRequiresAuthenticatedJsonRequestAndEnabledFeature(): void
    {
        $this->getJson('/auth/keycloak/provisioning/groups/pending.json');
        $this->assertResponseCode(401);

        [$manager, , , $membership] = $this->pendingMembership();
        $this->logInAs($manager);
        $this->post('/auth/keycloak/provisioning/groups/complete/' . $membership->id);
        $this->assertResponseCode(404);
        $this->assertSame(
            KeycloakSsoGroupMembership::STATUS_PENDING_CRYPTO,
            $this->memberships()->get($membership->id)->get('status')
        );

        putenv(KeycloakSsoEnvironment::GROUP_PROVISIONING_ENABLED . '=false');
        $this->getJson('/auth/keycloak/provisioning/groups/pending.json');
        $this->assertResponseCode(404);
        $this->postJson('/auth/keycloak/provisioning/groups/complete/' . $membership->id . '.json');
        $this->assertResponseCode(404);
        $this->assertSame(
            KeycloakSsoGroupMembership::STATUS_PENDING_CRYPTO,
            $this->memberships()->get($membership->id)->get('status')
        );
    }

    /**
     * @return array{
     *   0: \App\Model\Entity\User,
     *   1: \App\Model\Entity\User,
     *   2: \App\Model\Entity\Group,
     *   3: KeycloakSsoGroupMembership
     * }
     */
    private function pendingMembership(string $issuer = self::ISSUER): array
    {
        /** @var \App\Model\Entity\User $manager */
        $manager = UserFactory::make()->user()->active()->notDisabled()->persist();
        /** @var \App\Model\Entity\User $target */
        $target = UserFactory::make()->user()->active()->notDisabled()->persist();
        /** @var \App\Model\Entity\Group $group */
        $group = GroupFactory::make()->withGroupsManagersFor([$manager])->persist();
        /** @var \Passbolt\KeycloakSso\Model\Entity\KeycloakSsoProvisionedGroup $mapping */
        $mapping = $this->mappedGroups()->newEntity([
            'id' => UuidFactory::uuid(),
            'group_id' => $group->id,
            'issuer' => $issuer,
            'keycloak_group_id' => 'engineering-id',
            'keycloak_group_path' => '/Engineering',
        ], ['accessibleFields' => ['*' => true]]);
        $this->mappedGroups()->saveOrFail($mapping);
        /** @var KeycloakSsoGroupMembership $membership */
        $membership = $this->memberships()->newEntity([
            'id' => UuidFactory::uuid(),
            'provisioned_group_id' => $mapping->id,
            'user_id' => $target->id,
            'status' => KeycloakSsoGroupMembership::STATUS_PENDING_CRYPTO,
            'failure_code' => null,
        ], ['accessibleFields' => ['*' => true]]);
        $this->memberships()->saveOrFail($membership);

        return [$manager, $target, $group, $membership];
    }

    private function mappedGroups(): KeycloakSsoProvisionedGroupsTable
    {
        /** @var KeycloakSsoProvisionedGroupsTable $table */
        $table = TableRegistry::getTableLocator()->get('Passbolt/KeycloakSso.KeycloakSsoProvisionedGroups');

        return $table;
    }

    private function memberships(): KeycloakSsoGroupMembershipsTable
    {
        /** @var KeycloakSsoGroupMembershipsTable $table */
        $table = TableRegistry::getTableLocator()->get('Passbolt/KeycloakSso.KeycloakSsoGroupMemberships');

        return $table;
    }
}
