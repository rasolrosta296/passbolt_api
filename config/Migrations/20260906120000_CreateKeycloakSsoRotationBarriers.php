<?php
declare(strict_types=1);

use Migrations\AbstractMigration;

final class CreateKeycloakSsoRotationBarriers extends AbstractMigration
{
    /**
     * Create the server-authoritative per-user passphrase-rotation barrier.
     */
    public function change(): void
    {
        $uuid = ['null' => false, 'encoding' => 'ascii', 'collation' => 'ascii_general_ci'];
        $asciiText = ['null' => false, 'encoding' => 'ascii', 'collation' => 'ascii_general_ci'];

        $this->table('keycloak_sso_rotation_barriers', [
            'id' => false,
            'primary_key' => ['id'],
            'encoding' => 'utf8mb4',
            'collation' => 'utf8mb4_bin',
        ])
            ->addColumn('id', 'uuid', $uuid)
            ->addColumn('user_id', 'uuid', $uuid)
            ->addColumn('capability_hash', 'char', ['limit' => 64] + $asciiText)
            ->addColumn('capability_ciphertext', 'text', ['null' => true] + $asciiText)
            ->addColumn('status', 'string', ['limit' => 32] + $asciiText)
            ->addColumn('created', 'datetime', ['null' => false])
            ->addColumn('modified', 'datetime', ['null' => false])
            ->addColumn('finished', 'datetime', ['null' => true])
            ->addIndex(['user_id'], ['name' => 'uq_keycloak_rotation_barrier_user', 'unique' => true])
            ->addIndex(['status', 'modified'], ['name' => 'idx_keycloak_rotation_barrier_status'])
            ->addForeignKey('user_id', 'users', 'id', ['delete' => 'CASCADE', 'update' => 'RESTRICT'])
            ->create();
    }
}
