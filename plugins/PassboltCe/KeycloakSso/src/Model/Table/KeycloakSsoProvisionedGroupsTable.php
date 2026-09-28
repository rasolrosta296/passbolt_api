<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Table;

use Cake\ORM\RulesChecker;
use Cake\ORM\Table;
use Cake\Validation\Validator;

final class KeycloakSsoProvisionedGroupsTable extends Table
{
    /** Configure immutable Keycloak-group mappings. */
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->setTable('keycloak_sso_provisioned_groups');
        $this->setPrimaryKey('id');
        $this->addBehavior('Timestamp');
        $this->belongsTo('Groups', [
            'className' => 'Groups',
            'foreignKey' => 'group_id',
            'joinType' => 'INNER',
        ]);
        $this->hasMany('GroupMemberships', [
            'className' => 'Passbolt/KeycloakSso.KeycloakSsoGroupMemberships',
            'foreignKey' => 'provisioned_group_id',
        ]);
    }

    /** Validate immutable mapping fields. */
    public function validationDefault(Validator $validator): Validator
    {
        $validator
            ->uuid('id')->requirePresence('id', 'create')->notEmptyString('id')
            ->uuid('group_id')->requirePresence('group_id', 'create')->notEmptyString('group_id');

        foreach (['issuer', 'keycloak_group_id', 'keycloak_group_path'] as $field) {
            $validator
                ->scalar($field)->maxLength($field, 255)
                ->requirePresence($field, 'create')->notEmptyString($field);
        }

        return $validator;
    }

    /** Enforce one immutable provider group per Passbolt group. */
    public function buildRules(RulesChecker $rules): RulesChecker
    {
        $rules->add($rules->existsIn(['group_id'], 'Groups'), ['errorField' => 'group_id']);
        $rules->add($rules->isUnique(['issuer', 'keycloak_group_id']), ['errorField' => 'keycloak_group_id']);
        $rules->add($rules->isUnique(['group_id']), ['errorField' => 'group_id']);

        return $rules;
    }
}
