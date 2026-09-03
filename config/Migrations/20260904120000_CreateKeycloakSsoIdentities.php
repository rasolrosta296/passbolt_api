<?php
declare(strict_types=1);

use Migrations\AbstractMigration;

final class CreateKeycloakSsoIdentities extends AbstractMigration
{
    /**
     * Add purpose-bound link transactions and the persistent identity table.
     */
    public function change(): void
    {
        $this->table('keycloak_sso_transactions')
            ->addColumn('purpose', 'string', [
                'after' => 'redirect_uri',
                'default' => 'identity_proof',
                'limit' => 32,
                'null' => false,
                'encoding' => 'ascii',
                'collation' => 'ascii_bin',
            ])
            ->addColumn('requested_user_id', 'uuid', [
                'after' => 'purpose',
                'default' => null,
                'null' => true,
                'encoding' => 'ascii',
                'collation' => 'ascii_general_ci',
            ])
            ->addColumn('link_identity_ciphertext', 'text', [
                'after' => 'requested_user_id',
                'default' => null,
                'null' => true,
                'encoding' => 'ascii',
                'collation' => 'ascii_bin',
            ])
            ->addIndex(['purpose', 'status', 'result_expires'], [
                'name' => 'idx_keycloak_sso_transactions_result_purpose',
            ])
            ->addForeignKey('requested_user_id', 'users', 'id', [
                'delete' => 'CASCADE',
                'update' => 'RESTRICT',
            ])
            ->update();

        $this->table('keycloak_sso_identities', [
            'id' => false,
            'primary_key' => ['id'],
            'encoding' => 'utf8mb4',
            'collation' => 'utf8mb4_bin',
        ])
            ->addColumn('id', 'uuid', [
                'null' => false,
                'encoding' => 'ascii',
                'collation' => 'ascii_general_ci',
            ])
            ->addColumn('user_id', 'uuid', [
                'null' => false,
                'encoding' => 'ascii',
                'collation' => 'ascii_general_ci',
            ])
            ->addColumn('issuer', 'string', [
                'limit' => 255,
                'null' => false,
                'encoding' => 'utf8mb4',
                'collation' => 'utf8mb4_bin',
            ])
            ->addColumn('subject', 'string', [
                'limit' => 255,
                'null' => false,
                'encoding' => 'utf8mb4',
                'collation' => 'utf8mb4_bin',
            ])
            ->addColumn('email_at_link_time', 'string', [
                'limit' => 255,
                'null' => false,
                'encoding' => 'utf8mb4',
                'collation' => 'utf8mb4_bin',
            ])
            ->addColumn('created', 'datetime', ['null' => false])
            ->addColumn('modified', 'datetime', ['null' => false])
            ->addColumn('last_seen', 'datetime', ['null' => false])
            ->addIndex(['issuer', 'subject'], [
                'name' => 'uq_keycloak_sso_identities_provider_subject',
                'unique' => true,
            ])
            ->addIndex(['issuer', 'user_id'], [
                'name' => 'uq_keycloak_sso_identities_provider_user',
                'unique' => true,
            ])
            ->addIndex(['user_id'], ['name' => 'idx_keycloak_sso_identities_user'])
            ->addForeignKey('user_id', 'users', 'id', [
                'delete' => 'CASCADE',
                'update' => 'RESTRICT',
            ])
            ->create();
    }
}
