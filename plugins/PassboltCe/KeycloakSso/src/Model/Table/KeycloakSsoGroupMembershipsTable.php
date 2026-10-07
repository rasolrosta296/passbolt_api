<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Table;

use Cake\ORM\RulesChecker;
use Cake\ORM\Table;
use Cake\Validation\Validator;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoGroupMembership;

final class KeycloakSsoGroupMembershipsTable extends Table
{
    /** Configure desired Keycloak-to-Passbolt membership state. */
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->setTable('keycloak_sso_group_memberships');
        $this->setPrimaryKey('id');
        $this->addBehavior('Timestamp');
        $this->belongsTo('ProvisionedGroups', [
            'className' => 'Passbolt/KeycloakSso.KeycloakSsoProvisionedGroups',
            'foreignKey' => 'provisioned_group_id',
            'joinType' => 'INNER',
        ]);
        $this->belongsTo('Users', [
            'className' => 'Users',
            'foreignKey' => 'user_id',
            'joinType' => 'INNER',
        ]);
    }

    /** Validate fixed membership state. */
    public function validationDefault(Validator $validator): Validator
    {
        $validator
            ->uuid('id')->requirePresence('id', 'create')->notEmptyString('id')
            ->uuid('provisioned_group_id')->requirePresence('provisioned_group_id', 'create')
            ->notEmptyString('provisioned_group_id')
            ->uuid('user_id')->requirePresence('user_id', 'create')->notEmptyString('user_id')
            ->scalar('status')->inList('status', [
                KeycloakSsoGroupMembership::STATUS_PENDING_ACTIVATION,
                KeycloakSsoGroupMembership::STATUS_PENDING_CRYPTO,
                KeycloakSsoGroupMembership::STATUS_ACTIVE,
                KeycloakSsoGroupMembership::STATUS_FAILED,
                KeycloakSsoGroupMembership::STATUS_REVOKED,
            ])->requirePresence('status', 'create')->notEmptyString('status')
            ->scalar('failure_code')->maxLength('failure_code', 64)->allowEmptyString('failure_code');

        $validator->allowEmptyDateTime('revoked');

        return $validator;
    }

    /** Enforce one desired membership per mapped group and user. */
    public function buildRules(RulesChecker $rules): RulesChecker
    {
        $rules->add(
            $rules->existsIn(['provisioned_group_id'], 'ProvisionedGroups'),
            ['errorField' => 'provisioned_group_id']
        );
        $rules->add($rules->existsIn(['user_id'], 'Users'), ['errorField' => 'user_id']);
        $rules->add(
            $rules->isUnique(['provisioned_group_id', 'user_id']),
            ['errorField' => 'provisioned_group_id']
        );

        return $rules;
    }
}
