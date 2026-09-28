<?php
declare(strict_types=1);

use Migrations\AbstractMigration;

final class CreateKeycloakSsoGroupProvisioning extends AbstractMigration
{
    /** Create immutable Keycloak-group mappings and pending membership state. */
    public function change(): void
    {
        $uuid = ['null' => false, 'encoding' => 'ascii', 'collation' => 'ascii_general_ci'];
        $ascii = ['null' => false, 'encoding' => 'ascii', 'collation' => 'ascii_general_ci'];

        $this->table('keycloak_sso_provisioned_groups', [
            'id' => false,
            'primary_key' => ['id'],
            'encoding' => 'utf8mb4',
            'collation' => 'utf8mb4_bin',
        ])
            ->addColumn('id', 'uuid', $uuid)
            ->addColumn('group_id', 'uuid', $uuid)
            ->addColumn('issuer', 'string', ['limit' => 255, 'null' => false])
            ->addColumn('keycloak_group_id', 'string', ['limit' => 255, 'null' => false])
            ->addColumn('keycloak_group_path', 'string', ['limit' => 255, 'null' => false])
            ->addColumn('created', 'datetime', ['null' => false])
            ->addColumn('modified', 'datetime', ['null' => false])
            ->addIndex(['issuer', 'keycloak_group_id'], [
                'name' => 'uq_keycloak_provisioned_group_identity',
                'unique' => true,
            ])
            ->addIndex(['group_id'], ['name' => 'uq_keycloak_provisioned_group', 'unique' => true])
            ->addForeignKey('group_id', 'groups', 'id', ['delete' => 'RESTRICT', 'update' => 'RESTRICT'])
            ->create();

        $this->table('keycloak_sso_group_memberships', [
            'id' => false,
            'primary_key' => ['id'],
            'encoding' => 'utf8mb4',
            'collation' => 'utf8mb4_bin',
        ])
            ->addColumn('id', 'uuid', $uuid)
            ->addColumn('provisioned_group_id', 'uuid', $uuid)
            ->addColumn('user_id', 'uuid', $uuid)
            ->addColumn('status', 'string', ['limit' => 32] + $ascii)
            ->addColumn('failure_code', 'string', ['limit' => 64, 'null' => true] + $ascii)
            ->addColumn('created', 'datetime', ['null' => false])
            ->addColumn('modified', 'datetime', ['null' => false])
            ->addIndex(['provisioned_group_id', 'user_id'], [
                'name' => 'uq_keycloak_group_membership',
                'unique' => true,
            ])
            ->addIndex(['status', 'modified'], ['name' => 'idx_keycloak_group_membership_status'])
            ->addIndex(['user_id'], ['name' => 'idx_keycloak_group_membership_user'])
            ->addForeignKey(
                'provisioned_group_id',
                'keycloak_sso_provisioned_groups',
                'id',
                ['delete' => 'CASCADE', 'update' => 'RESTRICT']
            )
            ->addForeignKey('user_id', 'users', 'id', ['delete' => 'CASCADE', 'update' => 'RESTRICT'])
            ->create();
    }
}
