<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Model;

use App\Model\Entity\User;
use App\Test\Factory\UserFactory;
use App\Utility\UuidFactory;
use Cake\Database\Exception\QueryException;
use Cake\Datasource\Exception\RecordNotFoundException;
use Cake\ORM\TableRegistry;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoProvisioningEvent;
use Passbolt\KeycloakSso\Test\Lib\KeycloakSsoIntegrationTestCase;

final class ProvisioningPersistenceTest extends KeycloakSsoIntegrationTestCase
{
    public function testDatabaseConstraintRejectsDuplicateProviderEventWithoutApplicationRules(): void
    {
        $table = TableRegistry::getTableLocator()->get('Passbolt/KeycloakSso.KeycloakSsoProvisioningEvents');
        $data = [
            'id' => UuidFactory::uuid(),
            'event_id' => '8d020e76-4951-58d2-b68e-99e2fc1053f8',
            'issuer' => 'https://keyclock.gobaz.ir/realms/passbolt',
            'subject' => 'e2bc1228-043a-4512-8a91-f08683e55e53',
            'event_time' => 1_789_569_606_000,
            'operation' => 'CREATE',
            'status' => KeycloakSsoProvisioningEvent::STATUS_PENDING,
        ];

        $first = $table->newEntity($data, ['accessibleFields' => ['*' => true]]);
        $this->assertNotFalse($table->saveOrFail($first));
        $now = date('Y-m-d H:i:s');
        $this->expectException(QueryException::class);
        $table->getConnection()->insert($table->getTable(), [
            'id' => UuidFactory::uuid(),
            'event_id' => $data['event_id'],
            'issuer' => $data['issuer'],
            'subject' => $data['subject'],
            'event_time' => $data['event_time'],
            'operation' => $data['operation'],
            'status' => $data['status'],
            'user_id' => null,
            'failure_code' => null,
            'created' => $now,
            'modified' => $now,
        ]);
    }

    public function testDatabaseRejectsDuplicateProvisionedSubjectAndUser(): void
    {
        $user = UserFactory::make()->user()->persist();
        $otherUser = UserFactory::make()->user()->persist();
        $this->assertInstanceOf(User::class, $user);
        $this->assertInstanceOf(User::class, $otherUser);
        $table = TableRegistry::getTableLocator()->get('Passbolt/KeycloakSso.KeycloakSsoProvisionedUsers');
        $base = [
            'issuer' => 'https://keyclock.gobaz.ir/realms/passbolt',
            'subject' => 'e2bc1228-043a-4512-8a91-f08683e55e53',
            'email_at_provisioning' => 'provisioned@example.test',
            'source_event_id' => '8d020e76-4951-58d2-b68e-99e2fc1053f8',
        ];
        $first = $table->newEntity(
            ['id' => UuidFactory::uuid(), 'user_id' => $user->id] + $base,
            ['accessibleFields' => ['*' => true]]
        );
        $table->saveOrFail($first);

        $duplicateSubject = $table->newEntity([
            'id' => UuidFactory::uuid(),
            'user_id' => $otherUser->id,
            'source_event_id' => '7cd5488d-b1ec-42f6-925d-795620ff2701',
        ] + $base, ['accessibleFields' => ['*' => true]]);
        $this->assertFalse($table->save($duplicateSubject));

        $duplicateUser = $table->newEntity([
            'id' => UuidFactory::uuid(),
            'user_id' => $user->id,
            'subject' => '53a9a0c1-8ce8-4cbc-9b38-04938fea2311',
            'source_event_id' => '4d2d5c43-a76a-5d4a-8f47-2b1f0268e3d6',
        ] + $base, ['accessibleFields' => ['*' => true]]);
        $this->assertFalse($table->save($duplicateUser));
    }

    public function testProvisioningRecordsDoNotCreateIdentityLink(): void
    {
        $this->expectException(RecordNotFoundException::class);

        TableRegistry::getTableLocator()
            ->get('Passbolt/KeycloakSso.KeycloakSsoIdentities')
            ->find()
            ->firstOrFail();
    }
}
