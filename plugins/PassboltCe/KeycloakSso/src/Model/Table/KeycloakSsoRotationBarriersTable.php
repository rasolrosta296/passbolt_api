<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Table;

use Cake\ORM\RulesChecker;
use Cake\ORM\Table;
use Cake\Validation\Validator;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoRotationBarrier;

final class KeycloakSsoRotationBarriersTable extends Table
{
    /** Configure rotation-barrier persistence. */
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->setTable('keycloak_sso_rotation_barriers');
        $this->setPrimaryKey('id');
        $this->addBehavior('Timestamp');
        $this->belongsTo('Users', ['className' => 'Users', 'foreignKey' => 'user_id', 'joinType' => 'INNER']);
    }

    /** Validate the fixed barrier state model. */
    public function validationDefault(Validator $validator): Validator
    {
        $validator
            ->uuid('id')->requirePresence('id', 'create')->notEmptyString('id')
            ->uuid('user_id')->requirePresence('user_id', 'create')->notEmptyString('user_id')
            ->scalar('capability_hash')->lengthBetween('capability_hash', [64, 64])
            ->requirePresence('capability_hash', 'create')->notEmptyString('capability_hash')
            ->scalar('capability_ciphertext')->allowEmptyString('capability_ciphertext')
            ->scalar('status')->inList('status', [
                KeycloakSsoRotationBarrier::STATUS_ACTIVE,
                KeycloakSsoRotationBarrier::STATUS_COMPLETED,
                KeycloakSsoRotationBarrier::STATUS_FAILED,
            ])->requirePresence('status', 'create')
            ->dateTime('finished')->allowEmptyDateTime('finished');

        return $validator;
    }

    /** Enforce one barrier state row per user. */
    public function buildRules(RulesChecker $rules): RulesChecker
    {
        $rules->add($rules->existsIn(['user_id'], 'Users'), ['errorField' => 'user_id']);
        $rules->add($rules->isUnique(['user_id']), ['errorField' => 'user_id']);

        return $rules;
    }
}
