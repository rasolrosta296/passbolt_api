<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Table;

use Cake\ORM\RulesChecker;
use Cake\ORM\Table;
use Cake\Validation\Validator;
use Passbolt\KeycloakSso\Cryptography\Protocol\CborProtocolV1;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoCryptoEnrollment;

final class KeycloakSsoCryptoEnrollmentsTable extends Table
{
    /**
     * Configure enrollment persistence and associations.
     */
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->setTable('keycloak_sso_crypto_enrollments');
        $this->setPrimaryKey('id');
        $this->addBehavior('Timestamp');
        $this->belongsTo('Users', ['className' => 'Users', 'foreignKey' => 'user_id', 'joinType' => 'INNER']);
        $this->belongsTo('Identities', [
            'className' => 'Passbolt/KeycloakSso.KeycloakSsoIdentities',
            'foreignKey' => 'identity_id',
            'joinType' => 'INNER',
        ]);
    }

    /**
     * Validate cryptographic enrollment records.
     */
    public function validationDefault(Validator $validator): Validator
    {
        foreach (['id', 'user_id', 'identity_id', 'client_enrollment_uuid'] as $field) {
            $validator->uuid($field)->requirePresence($field, 'create')->notEmptyString($field);
        }
        $validator
            ->scalar('context_cbor')
            ->maxLength('context_cbor', 4096)
            ->requirePresence('context_cbor', 'create')
            ->notEmptyString('context_cbor')
            ->scalar('signing_public_key')
            ->maxLength('signing_public_key', 2048)
            ->requirePresence('signing_public_key', 'create')
            ->notEmptyString('signing_public_key')
            ->ascii('signing_key_thumbprint')
            ->lengthBetween('signing_key_thumbprint', [43, 43])
            ->requirePresence('signing_key_thumbprint', 'create')
            ->notEmptyString('signing_key_thumbprint')
            ->ascii('server_share_ciphertext')
            ->maxLength('server_share_ciphertext', 128)
            ->requirePresence('server_share_ciphertext', 'create')
            ->notEmptyString('server_share_ciphertext')
            ->ascii('server_share_nonce')
            ->lengthBetween('server_share_nonce', [32, 32])
            ->requirePresence('server_share_nonce', 'create')
            ->notEmptyString('server_share_nonce')
            ->ascii('server_share_key_id')
            ->maxLength('server_share_key_id', 64)
            ->requirePresence('server_share_key_id', 'create')
            ->notEmptyString('server_share_key_id')
            ->ascii('client_blob_digest')
            ->lengthBetween('client_blob_digest', [64, 64])
            ->requirePresence('client_blob_digest', 'create')
            ->notEmptyString('client_blob_digest')
            ->ascii('passbolt_key_fingerprint')
            ->lengthBetween('passbolt_key_fingerprint', [40, 40])
            ->requirePresence('passbolt_key_fingerprint', 'create')
            ->notEmptyString('passbolt_key_fingerprint')
            ->scalar('protocol_version')
            ->inList('protocol_version', [CborProtocolV1::VERSION])
            ->requirePresence('protocol_version', 'create')
            ->scalar('crypto_suite')
            ->inList('crypto_suite', [CborProtocolV1::SUITE])
            ->requirePresence('crypto_suite', 'create')
            ->scalar('status')
            ->inList('status', [
                KeycloakSsoCryptoEnrollment::STATUS_ACTIVE,
                KeycloakSsoCryptoEnrollment::STATUS_REVOKED,
            ])
            ->requirePresence('status', 'create')
            ->allowEmptyDateTime('last_used')
            ->allowEmptyDateTime('revoked');

        return $validator;
    }

    /**
     * Add relational and uniqueness rules.
     */
    public function buildRules(RulesChecker $rules): RulesChecker
    {
        $rules->add($rules->existsIn(['user_id'], 'Users'), ['errorField' => 'user_id']);
        $rules->add($rules->existsIn(['identity_id'], 'Identities'), ['errorField' => 'identity_id']);
        $rules->add(
            $rules->isUnique(['user_id', 'client_enrollment_uuid']),
            ['errorField' => 'client_enrollment_uuid']
        );
        $rules->add(
            $rules->isUnique(['identity_id', 'client_enrollment_uuid']),
            ['errorField' => 'client_enrollment_uuid']
        );

        return $rules;
    }
}
