<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Table;

use Cake\ORM\RulesChecker;
use Cake\ORM\Table;
use Cake\Validation\Validator;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoProvisioningEvent;

final class KeycloakSsoProvisioningEventsTable extends Table
{
    /** Configure replay-safe administrator event persistence. */
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->setTable('keycloak_sso_provisioning_events');
        $this->setPrimaryKey('id');
        $this->addBehavior('Timestamp');
        $this->belongsTo('Users', [
            'className' => 'Users',
            'foreignKey' => 'user_id',
        ]);
    }

    /** Validate the fixed administrator event state model. */
    public function validationDefault(Validator $validator): Validator
    {
        $validator
            ->uuid('id')->requirePresence('id', 'create')->notEmptyString('id')
            ->scalar('event_id')->maxLength('event_id', 64)
            ->requirePresence('event_id', 'create')->notEmptyString('event_id')
            ->scalar('issuer')->maxLength('issuer', 255)
            ->requirePresence('issuer', 'create')->notEmptyString('issuer')
            ->scalar('subject')->maxLength('subject', 255)
            ->requirePresence('subject', 'create')->notEmptyString('subject')
            ->nonNegativeInteger('event_time')->requirePresence('event_time', 'create')
            ->scalar('operation')->inList('operation', ['CREATE', 'UPDATE'])
            ->requirePresence('operation', 'create')
            ->scalar('status')->inList('status', [
                KeycloakSsoProvisioningEvent::STATUS_PENDING,
                KeycloakSsoProvisioningEvent::STATUS_PROCESSING,
                KeycloakSsoProvisioningEvent::STATUS_PROVISIONED,
                KeycloakSsoProvisioningEvent::STATUS_SKIPPED,
                KeycloakSsoProvisioningEvent::STATUS_COLLISION,
                KeycloakSsoProvisioningEvent::STATUS_FAILED,
            ])->requirePresence('status', 'create')
            ->uuid('user_id')->allowEmptyString('user_id')
            ->scalar('failure_code')->maxLength('failure_code', 64)->allowEmptyString('failure_code');

        return $validator;
    }

    /** Enforce event idempotency and optional Passbolt user ownership. */
    public function buildRules(RulesChecker $rules): RulesChecker
    {
        $rules->add($rules->existsIn(['user_id'], 'Users', ['allowNullableNulls' => true]), [
            'errorField' => 'user_id',
        ]);
        $rules->add($rules->isUnique(['issuer', 'event_id']), ['errorField' => 'event_id']);

        return $rules;
    }
}
