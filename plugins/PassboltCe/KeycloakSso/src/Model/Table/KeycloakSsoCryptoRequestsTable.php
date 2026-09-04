<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Table;

use Cake\ORM\RulesChecker;
use Cake\ORM\Table;
use Cake\Validation\Validator;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoCryptoRequest;

final class KeycloakSsoCryptoRequestsTable extends Table
{
    /**
     * Configure one-time cryptographic request persistence.
     */
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->setTable('keycloak_sso_crypto_requests');
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
     * Validate one-time cryptographic requests.
     */
    public function validationDefault(Validator $validator): Validator
    {
        foreach (['id', 'user_id', 'identity_id', 'enrollment_id'] as $field) {
            $validator->uuid($field)->requirePresence($field, 'create')->notEmptyString($field);
        }
        $validator
            ->scalar('purpose')
            ->inList('purpose', [
                KeycloakSsoCryptoRequest::PURPOSE_ENROLLMENT,
                KeycloakSsoCryptoRequest::PURPOSE_RELEASE,
            ])
            ->requirePresence('purpose', 'create')
            ->allowEmptyString('request_ciphertext')
            ->allowEmptyString('client_nonce_hash')
            ->scalar('status')->inList('status', [
                KeycloakSsoCryptoRequest::STATUS_PENDING_OIDC,
                KeycloakSsoCryptoRequest::STATUS_OIDC_VERIFIED,
                KeycloakSsoCryptoRequest::STATUS_PROCESSING,
                KeycloakSsoCryptoRequest::STATUS_CONSUMED,
                KeycloakSsoCryptoRequest::STATUS_FAILED,
            ])->requirePresence('status', 'create')
            ->dateTime('expires')->requirePresence('expires', 'create')->notEmptyDateTime('expires');

        return $validator;
    }

    /**
     * Add relational and nonce uniqueness rules.
     */
    public function buildRules(RulesChecker $rules): RulesChecker
    {
        $rules->add($rules->existsIn(['user_id'], 'Users'), ['errorField' => 'user_id']);
        $rules->add($rules->existsIn(['identity_id'], 'Identities'), ['errorField' => 'identity_id']);
        $rules->add($rules->isUnique(['client_nonce_hash']), ['errorField' => 'client_nonce_hash']);

        return $rules;
    }
}
