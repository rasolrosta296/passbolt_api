<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Table;

use Cake\ORM\RulesChecker;
use Cake\ORM\Table;
use Cake\Validation\Validator;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction;

final class KeycloakSsoTransactionsTable extends Table
{
    /**
     * Configure the transaction table.
     */
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->setTable('keycloak_sso_transactions');
        $this->setPrimaryKey('id');
        $this->addBehavior('Timestamp');
        $this->belongsTo('Users', [
            'className' => 'Users',
            'foreignKey' => 'requested_user_id',
        ]);
    }

    /**
     * Validate transaction persistence fields.
     */
    public function validationDefault(Validator $validator): Validator
    {
        $validator
            ->uuid('id')
            ->requirePresence('id', 'create')
            ->notEmptyString('id');

        foreach (['state_hash', 'nonce_hash', 'browser_binding_hash', 'configuration_hash'] as $field) {
            $validator
                ->ascii($field)
                ->lengthBetween($field, [64, 64])
                ->requirePresence($field, 'create')
                ->notEmptyString($field);
        }

        $validator
            ->scalar('pkce_verifier_ciphertext')
            ->requirePresence('pkce_verifier_ciphertext', 'create')
            ->notEmptyString('pkce_verifier_ciphertext')
            ->scalar('issuer')
            ->maxLength('issuer', 255)
            ->requirePresence('issuer', 'create')
            ->notEmptyString('issuer')
            ->scalar('client_id')
            ->maxLength('client_id', 255)
            ->requirePresence('client_id', 'create')
            ->notEmptyString('client_id')
            ->scalar('redirect_uri')
            ->requirePresence('redirect_uri', 'create')
            ->notEmptyString('redirect_uri')
            ->scalar('purpose')
            ->inList('purpose', [
                KeycloakSsoTransaction::PURPOSE_IDENTITY_PROOF,
                KeycloakSsoTransaction::PURPOSE_IDENTITY_LINK,
            ])
            ->requirePresence('purpose', 'create')
            ->notEmptyString('purpose')
            ->allowEmptyString('requested_user_id')
            ->allowEmptyString('link_identity_ciphertext')
            ->scalar('status')
            ->maxLength('status', 32)
            ->requirePresence('status', 'create')
            ->notEmptyString('status')
            ->dateTime('expires')
            ->requirePresence('expires', 'create')
            ->notEmptyDateTime('expires')
            ->allowEmptyString('result_token_hash')
            ->allowEmptyString('failure_code')
            ->allowEmptyDateTime('result_expires');

        return $validator;
    }

    /**
     * Enforce unique one-time transaction handles.
     */
    public function buildRules(RulesChecker $rules): RulesChecker
    {
        $rules->add($rules->isUnique(['state_hash']), ['errorField' => 'state_hash']);
        $rules->add($rules->isUnique(['result_token_hash']), ['errorField' => 'result_token_hash']);
        $rules->add($rules->existsIn(['requested_user_id'], 'Users', ['allowNullableNulls' => true]), [
            'errorField' => 'requested_user_id',
        ]);

        return $rules;
    }
}
