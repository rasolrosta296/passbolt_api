<?php
declare(strict_types=1);

use Migrations\AbstractMigration;

final class CreateKeycloakSsoProvisioning extends AbstractMigration
{
    /** Create replay-safe provisioning event and provisioned-user records. */
    public function change(): void
    {
        $uuid = ['null' => false, 'encoding' => 'ascii', 'collation' => 'ascii_general_ci'];
        $ascii = ['null' => false, 'encoding' => 'ascii', 'collation' => 'ascii_general_ci'];

        $this->table('keycloak_sso_provisioning_events', [
            'id' => false,
            'primary_key' => ['id'],
            'encoding' => 'utf8mb4',
            'collation' => 'utf8mb4_bin',
        ])
            ->addColumn('id', 'uuid', $uuid)
            ->addColumn('event_id', 'string', ['limit' => 64] + $ascii)
            ->addColumn('issuer', 'string', ['limit' => 255, 'null' => false])
            ->addColumn('subject', 'string', ['limit' => 255, 'null' => false])
            ->addColumn('event_time', 'biginteger', ['null' => false, 'signed' => false])
            ->addColumn('operation', 'string', ['limit' => 16] + $ascii)
            ->addColumn('status', 'string', ['limit' => 32] + $ascii)
            ->addColumn('user_id', 'uuid', ['null' => true] + $uuid)
            ->addColumn('failure_code', 'string', ['limit' => 64, 'null' => true] + $ascii)
            ->addColumn('created', 'datetime', ['null' => false])
            ->addColumn('modified', 'datetime', ['null' => false])
            ->addIndex(['issuer', 'event_id'], [
                'name' => 'uq_keycloak_provisioning_event',
                'unique' => true,
            ])
            ->addIndex(['status', 'event_time'], ['name' => 'idx_keycloak_provisioning_event_status'])
            ->addIndex(['issuer', 'subject'], ['name' => 'idx_keycloak_provisioning_event_subject'])
            ->addForeignKey('user_id', 'users', 'id', ['delete' => 'CASCADE', 'update' => 'RESTRICT'])
            ->create();

        $this->table('keycloak_sso_provisioned_users', [
            'id' => false,
            'primary_key' => ['id'],
            'encoding' => 'utf8mb4',
            'collation' => 'utf8mb4_bin',
        ])
            ->addColumn('id', 'uuid', $uuid)
            ->addColumn('user_id', 'uuid', $uuid)
            ->addColumn('issuer', 'string', ['limit' => 255, 'null' => false])
            ->addColumn('subject', 'string', ['limit' => 255, 'null' => false])
            ->addColumn('email_at_provisioning', 'string', ['limit' => 255, 'null' => false])
            ->addColumn('source_event_id', 'string', ['limit' => 64] + $ascii)
            ->addColumn('created', 'datetime', ['null' => false])
            ->addColumn('modified', 'datetime', ['null' => false])
            ->addIndex(['issuer', 'subject'], [
                'name' => 'uq_keycloak_provisioned_subject',
                'unique' => true,
            ])
            ->addIndex(['user_id'], ['name' => 'uq_keycloak_provisioned_user', 'unique' => true])
            ->addIndex(['issuer', 'source_event_id'], [
                'name' => 'uq_keycloak_provisioned_event',
                'unique' => true,
            ])
            ->addForeignKey('user_id', 'users', 'id', ['delete' => 'CASCADE', 'update' => 'RESTRICT'])
            ->create();
    }
}
