<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Service\Crypto;

use App\Model\Entity\User;
use App\Test\Factory\UserFactory;
use App\Utility\UuidFactory;
use Cake\Database\Exception\QueryException;
use Cake\Datasource\ConnectionManager;
use Cake\I18n\DateTime;
use Cake\ORM\TableRegistry;
use Passbolt\KeycloakSso\Error\Exception\CryptoSsoException;
use Passbolt\KeycloakSso\Model\Dto\PendingIdentityLink;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoCryptoRequest;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoRotationBarrier;
use Passbolt\KeycloakSso\Service\Crypto\RevokeCryptoEnrollmentsService;
use Passbolt\KeycloakSso\Service\Crypto\RotationBarrierService;
use Passbolt\KeycloakSso\Service\Identity\IdentityLinkPersistenceService;
use Passbolt\KeycloakSso\Service\Transaction\TransactionSecretProtector;
use Passbolt\KeycloakSso\Test\Lib\KeycloakSsoIntegrationTestCase;

final class RotationBarrierServiceTest extends KeycloakSsoIntegrationTestCase
{
    private const ISSUER = 'https://keyclock.gobaz.ir/realms/passbolt';

    public function testActiveBarrierIsIdempotentAndCapabilityBound(): void
    {
        $user = $this->user();
        $service = $this->service();

        $first = $service->begin($user->id);
        $second = $service->begin($user->id);

        $this->assertSame($first, $second);
        $this->expectException(CryptoSsoException::class);
        $service->finish(str_repeat('a', 43), $user->id, KeycloakSsoRotationBarrier::STATUS_COMPLETED);
    }

    public function testBarrierInvalidatesPendingEnrollmentWithoutExistingEnrollment(): void
    {
        $user = $this->user();
        $identity = (new IdentityLinkPersistenceService())->create($user->id, new PendingIdentityLink(
            self::ISSUER,
            UuidFactory::uuid(),
            $user->username
        ));
        $requests = TableRegistry::getTableLocator()->get('Passbolt/KeycloakSso.KeycloakSsoCryptoRequests');
        $request = $requests->newEmptyEntity();
        foreach (
            [
            'id' => UuidFactory::uuid(),
            'purpose' => KeycloakSsoCryptoRequest::PURPOSE_ENROLLMENT,
            'user_id' => $user->id,
            'identity_id' => $identity->id,
            'enrollment_id' => UuidFactory::uuid(),
            'status' => KeycloakSsoCryptoRequest::STATUS_OIDC_VERIFIED,
            'expires' => DateTime::now()->addMinutes(5),
            ] as $field => $value
        ) {
            $request->set($field, $value);
        }
        $requests->saveOrFail($request);
        self::assertInstanceOf(KeycloakSsoCryptoRequest::class, $request);

        $result = $this->service()->begin($user->id);

        $this->assertSame([], $result['clientEnrollmentUuids']);
        $request = $requests->get($request->id);
        self::assertInstanceOf(KeycloakSsoCryptoRequest::class, $request);
        $this->assertSame(KeycloakSsoCryptoRequest::STATUS_FAILED, $request->status);
        $this->assertNull($request->request_ciphertext);
        $this->assertNull($request->client_nonce_hash);
    }

    public function testFinishIsIdempotentAndNeverReopensForOppositeOutcome(): void
    {
        $user = $this->user();
        $service = $this->service();
        $started = $service->begin($user->id);
        $service->finish(
            $started['capability'],
            $user->id,
            KeycloakSsoRotationBarrier::STATUS_COMPLETED
        );
        $service->finish(
            $started['capability'],
            $user->id,
            KeycloakSsoRotationBarrier::STATUS_COMPLETED
        );
        $service->assertInactive($user->id);

        $this->expectException(CryptoSsoException::class);
        $service->finish($started['capability'], $user->id, KeycloakSsoRotationBarrier::STATUS_FAILED);
    }

    public function testActiveBarrierRejectsNewCryptographicOperations(): void
    {
        $user = $this->user();
        $service = $this->service();
        $service->begin($user->id);

        $this->expectException(CryptoSsoException::class);
        $service->assertInactive($user->id);
    }

    public function testCapabilityCannotFinishAnotherUsersBarrier(): void
    {
        $firstUser = $this->user();
        $secondUser = $this->user();
        $service = $this->service();
        $first = $service->begin($firstUser->id);
        $second = $service->begin($secondUser->id);
        $this->assertNotSame($first['capability'], $second['capability']);

        $this->expectException(CryptoSsoException::class);
        $service->finish(
            $first['capability'],
            $secondUser->id,
            KeycloakSsoRotationBarrier::STATUS_COMPLETED
        );
    }

    public function testDatabaseUniquenessPermitsOnlyOneBarrierRowPerUser(): void
    {
        $user = $this->user();
        $this->service()->begin($user->id);
        $now = DateTime::now();

        $this->expectException(QueryException::class);
        /** @var \Cake\Database\Connection $connection */
        $connection = ConnectionManager::get('default');
        $connection->insert('keycloak_sso_rotation_barriers', [
            'id' => UuidFactory::uuid(),
            'user_id' => $user->id,
            'capability_hash' => hash('sha256', random_bytes(32)),
            'capability_ciphertext' => null,
            'status' => KeycloakSsoRotationBarrier::STATUS_ACTIVE,
            'created' => $now,
            'modified' => $now,
            'finished' => null,
        ]);
    }

    private function service(): RotationBarrierService
    {
        return new RotationBarrierService(
            new TransactionSecretProtector(str_repeat('T', 32)),
            new RevokeCryptoEnrollmentsService()
        );
    }

    private function user(): User
    {
        $user = UserFactory::make(['username' => UuidFactory::uuid() . '@example.com'])
            ->user()->active()->notDisabled()->persist();
        self::assertInstanceOf(User::class, $user);

        return $user;
    }
}
