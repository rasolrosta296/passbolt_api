<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Table;

use Cake\ORM\RulesChecker;
use Cake\ORM\Table;
use Cake\Validation\Validator;

final class KeycloakSsoProvisionedUsersTable extends Table
{
    /** Configure non-authenticating provisioning provenance records. */
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->setTable('keycloak_sso_provisioned_users');
        $this->setPrimaryKey('id');
        $this->addBehavior('Timestamp');
        $this->belongsTo('Users', [
            'className' => 'Users',
            'foreignKey' => 'user_id',
            'joinType' => 'INNER',
        ]);
    }

    /** Validate immutable provisioning provenance. */
    public function validationDefault(Validator $validator): Validator
    {
        $validator
            ->uuid('id')->requirePresence('id', 'create')->notEmptyString('id')
            ->uuid('user_id')->requirePresence('user_id', 'create')->notEmptyString('user_id');

        foreach (['issuer', 'subject', 'email_at_provisioning'] as $field) {
            $validator
                ->scalar($field)->maxLength($field, 255)
                ->requirePresence($field, 'create')->notEmptyString($field);
        }

        $validator
            ->scalar('source_event_id')->maxLength('source_event_id', 64)
            ->requirePresence('source_event_id', 'create')->notEmptyString('source_event_id');

        return $validator;
    }

    /** Enforce one provider subject and one provisioning record per user. */
    public function buildRules(RulesChecker $rules): RulesChecker
    {
        $rules->add($rules->existsIn(['user_id'], 'Users'), ['errorField' => 'user_id']);
        $rules->add($rules->isUnique(['issuer', 'subject']), ['errorField' => 'subject']);
        $rules->add($rules->isUnique(['user_id']), ['errorField' => 'user_id']);
        $rules->add($rules->isUnique(['issuer', 'source_event_id']), ['errorField' => 'source_event_id']);

        return $rules;
    }
}
