<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Service\Crypto;

use App\Test\Factory\UserFactory;
use App\Utility\UuidFactory;
use Cake\ORM\TableRegistry;
use Passbolt\KeycloakSso\Cryptography\Protocol\CborProtocolV1;
use Passbolt\KeycloakSso\Cryptography\ServerShareProtector;
use Passbolt\KeycloakSso\Model\Dto\CryptoConfigurationDto;
use Passbolt\KeycloakSso\Model\Dto\PendingIdentityLink;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoCryptoEnrollment;
use Passbolt\KeycloakSso\Service\Crypto\RewrapServerSharesService;
use Passbolt\KeycloakSso\Service\Identity\IdentityLinkPersistenceService;
use Passbolt\KeycloakSso\Test\Lib\KeycloakSsoIntegrationTestCase;

final class RewrapServerSharesServiceTest extends KeycloakSsoIntegrationTestCase
{
    public function testRewrapIsSafeToRetryAndLeavesNoActiveRowOnTheRetiredKey(): void
    {
        $oldKey = random_bytes(32);
        $newKey = random_bytes(32);
        $oldConfiguration = $this->configuration('old', ['old' => $oldKey]);
        $newConfiguration = $this->configuration('new', ['old' => $oldKey, 'new' => $newKey]);
        /** @var \App\Model\Entity\User $user */
        $user = UserFactory::make(['username' => UuidFactory::uuid() . '@example.test'])
            ->user()->active()->notDisabled()->persist();
        $identity = (new IdentityLinkPersistenceService())->create($user->id, new PendingIdentityLink(
            'https://keyclock.gobaz.ir/realms/passbolt',
            UuidFactory::uuid(),
            $user->username
        ));
        $enrollmentId = UuidFactory::uuid();
        $context = [
            'protocol_version' => CborProtocolV1::VERSION,
            'crypto_suite' => CborProtocolV1::SUITE,
            'passbolt_origin' => 'https://passbolt.example.test',
            'user_uuid' => $user->id,
            'identity_uuid' => $identity->id,
            'enrollment_uuid' => $enrollmentId,
            'client_enrollment_uuid' => UuidFactory::uuid(),
            'openpgp_fingerprint' => str_repeat('A', 40),
            'enrollment_public_key_thumbprint' => str_repeat('t', 43),
        ];
        $contextBytes = CborProtocolV1::encodeContext($context);
        $aad = CborProtocolV1::encodeBinding('release_package', $context);
        $share = random_bytes(32);
        $protected = (new ServerShareProtector($oldConfiguration))->encrypt($share, $aad);

        $table = TableRegistry::getTableLocator()
            ->get('Passbolt/KeycloakSso.KeycloakSsoCryptoEnrollments');
        $entity = $table->newEmptyEntity();
        foreach (
            [
                'id' => $enrollmentId,
                'user_id' => $user->id,
                'identity_id' => $identity->id,
                'client_enrollment_uuid' => $context['client_enrollment_uuid'],
                'context_cbor' => base64_encode($contextBytes),
                'signing_public_key' => '{"kty":"EC"}',
                'signing_key_thumbprint' => $context['enrollment_public_key_thumbprint'],
                'server_share_ciphertext' => $protected['ciphertext'],
                'server_share_nonce' => $protected['nonce'],
                'server_share_key_id' => $protected['keyId'],
                'client_blob_digest' => str_repeat('b', 64),
                'passbolt_key_fingerprint' => $context['openpgp_fingerprint'],
                'protocol_version' => CborProtocolV1::VERSION,
                'crypto_suite' => CborProtocolV1::SUITE,
                'status' => KeycloakSsoCryptoEnrollment::STATUS_ACTIVE,
            ] as $field => $value
        ) {
            $entity->set($field, $value);
        }
        $table->saveOrFail($entity);

        $service = new RewrapServerSharesService(
            $newConfiguration,
            new ServerShareProtector($newConfiguration)
        );
        $this->assertSame(1, $service->rewrap());
        $rewrapped = $table->get($enrollmentId);
        $firstCiphertext = (string)$rewrapped->get('server_share_ciphertext');
        $this->assertSame('new', $rewrapped->get('server_share_key_id'));
        $this->assertNotSame($protected['ciphertext'], $firstCiphertext);
        $this->assertSame($share, (new ServerShareProtector($newConfiguration))->decrypt(
            $firstCiphertext,
            (string)$rewrapped->get('server_share_nonce'),
            (string)$rewrapped->get('server_share_key_id'),
            $aad
        ));

        $this->assertSame(0, $service->rewrap());
        $this->assertSame($firstCiphertext, $table->get($enrollmentId)->get('server_share_ciphertext'));
        $this->assertSame(0, $table->find()->where([
            'status' => KeycloakSsoCryptoEnrollment::STATUS_ACTIVE,
            'revoked IS' => null,
            'server_share_key_id' => 'old',
        ])->count());
    }

    /** @param array<string, string> $keys */
    private function configuration(string $active, array $keys): CryptoConfigurationDto
    {
        return new CryptoConfigurationDto('https://passbolt.example.test', 'mfa', [], $active, $keys);
    }
}
