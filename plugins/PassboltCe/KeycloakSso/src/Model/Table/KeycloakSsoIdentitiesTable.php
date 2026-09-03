<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Table;

use Cake\ORM\RulesChecker;
use Cake\ORM\Table;
use Cake\Validation\Validator;

final class KeycloakSsoIdentitiesTable extends Table
{
    /**
     * Configure the plugin-owned immutable identity mapping table.
     */
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->setTable('keycloak_sso_identities');
        $this->setPrimaryKey('id');
        $this->addBehavior('Timestamp');
        $this->belongsTo('Users', [
            'className' => 'Users',
            'foreignKey' => 'user_id',
            'joinType' => 'INNER',
        ]);
    }

    /**
     * Validate opaque, case-sensitive identity values without normalization.
     */
    public function validationDefault(Validator $validator): Validator
    {
        $validator
            ->uuid('id')
            ->requirePresence('id', 'create')
            ->notEmptyString('id')
            ->uuid('user_id')
            ->requirePresence('user_id', 'create')
            ->notEmptyString('user_id');

        foreach (['issuer', 'subject', 'email_at_link_time'] as $field) {
            $validator
                ->scalar($field)
                ->maxLength($field, 255)
                ->requirePresence($field, 'create')
                ->notEmptyString($field);
        }

        $validator
            ->dateTime('last_seen')
            ->requirePresence('last_seen', 'create')
            ->notEmptyDateTime('last_seen');

        return $validator;
    }

    /**
     * Mirror database ownership and collision rules for useful validation errors.
     */
    public function buildRules(RulesChecker $rules): RulesChecker
    {
        $rules->add($rules->existsIn(['user_id'], 'Users'), ['errorField' => 'user_id']);
        $rules->add($rules->isUnique(['issuer', 'subject']), ['errorField' => 'subject']);
        $rules->add($rules->isUnique(['issuer', 'user_id']), ['errorField' => 'user_id']);

        return $rules;
    }
}
