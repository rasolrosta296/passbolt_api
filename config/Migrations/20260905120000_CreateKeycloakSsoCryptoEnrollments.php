<?php
declare(strict_types=1);

use Migrations\AbstractMigration;

final class CreateKeycloakSsoCryptoEnrollments extends AbstractMigration
{
    /**
     * Create browser-profile enrollments and one-time crypto requests.
     */
    public function change(): void
    {
        $uuid = ['null' => false, 'encoding' => 'ascii', 'collation' => 'ascii_general_ci'];
        $asciiText = ['null' => false, 'encoding' => 'ascii', 'collation' => 'ascii_general_ci'];
        $asciiNullableText = ['null' => true, 'encoding' => 'ascii', 'collation' => 'ascii_general_ci'];

        $this->table('keycloak_sso_crypto_enrollments', [
            'id' => false,
            'primary_key' => ['id'],
            'encoding' => 'utf8mb4',
            'collation' => 'utf8mb4_bin',
        ])
            ->addColumn('id', 'uuid', $uuid)
            ->addColumn('user_id', 'uuid', $uuid)
            ->addColumn('identity_id', 'uuid', $uuid)
            ->addColumn('client_enrollment_uuid', 'uuid', $uuid)
            ->addColumn('context_cbor', 'text', $asciiText)
            ->addColumn('signing_public_key', 'text', $asciiText)
            ->addColumn('signing_key_thumbprint', 'char', ['limit' => 43] + $asciiText)
            ->addColumn('server_share_ciphertext', 'text', $asciiText)
            ->addColumn('server_share_nonce', 'char', ['limit' => 32] + $asciiText)
            ->addColumn('server_share_key_id', 'string', ['limit' => 64] + $asciiText)
            ->addColumn('client_blob_digest', 'char', ['limit' => 64] + $asciiText)
            ->addColumn('passbolt_key_fingerprint', 'char', ['limit' => 40] + $asciiText)
            ->addColumn('protocol_version', 'string', ['limit' => 64] + $asciiText)
            ->addColumn('crypto_suite', 'string', ['limit' => 128] + $asciiText)
            ->addColumn('status', 'string', ['limit' => 32] + $asciiText)
            ->addColumn('created', 'datetime', ['null' => false])
            ->addColumn('modified', 'datetime', ['null' => false])
            ->addColumn('last_used', 'datetime', ['null' => true])
            ->addColumn('revoked', 'datetime', ['null' => true])
            ->addIndex(
                ['user_id', 'client_enrollment_uuid'],
                ['name' => 'uq_keycloak_crypto_user_client', 'unique' => true]
            )
            ->addIndex(
                ['identity_id', 'client_enrollment_uuid'],
                ['name' => 'uq_keycloak_crypto_identity_client', 'unique' => true]
            )
            ->addIndex(['identity_id', 'status'], ['name' => 'idx_keycloak_crypto_identity_status'])
            ->addIndex(['user_id', 'status'], ['name' => 'idx_keycloak_crypto_user_status'])
            ->addForeignKey('user_id', 'users', 'id', ['delete' => 'CASCADE', 'update' => 'RESTRICT'])
            ->addForeignKey(
                'identity_id',
                'keycloak_sso_identities',
                'id',
                ['delete' => 'CASCADE', 'update' => 'RESTRICT']
            )
            ->create();

        $this->table('keycloak_sso_crypto_requests', [
            'id' => false,
            'primary_key' => ['id'],
            'encoding' => 'utf8mb4',
            'collation' => 'utf8mb4_bin',
        ])
            ->addColumn('id', 'uuid', $uuid)
            ->addColumn('purpose', 'string', ['limit' => 32] + $asciiText)
            ->addColumn('user_id', 'uuid', $uuid)
            ->addColumn('identity_id', 'uuid', $uuid)
            ->addColumn('enrollment_id', 'uuid', $uuid)
            ->addColumn('request_ciphertext', 'text', $asciiNullableText)
            ->addColumn('client_nonce_hash', 'char', [
                'limit' => 64,
                'null' => true,
                'encoding' => 'ascii',
                'collation' => 'ascii_general_ci',
            ])
            ->addColumn('status', 'string', ['limit' => 32] + $asciiText)
            ->addColumn('expires', 'datetime', ['null' => false])
            ->addColumn('created', 'datetime', ['null' => false])
            ->addColumn('modified', 'datetime', ['null' => false])
            ->addIndex(['client_nonce_hash'], ['name' => 'uq_keycloak_crypto_request_nonce', 'unique' => true])
            ->addIndex(['enrollment_id', 'status'], ['name' => 'idx_keycloak_crypto_request_enrollment'])
            ->addIndex(['status', 'expires'], ['name' => 'idx_keycloak_crypto_request_expiry'])
            ->addForeignKey('user_id', 'users', 'id', ['delete' => 'CASCADE', 'update' => 'RESTRICT'])
            ->addForeignKey(
                'identity_id',
                'keycloak_sso_identities',
                'id',
                ['delete' => 'CASCADE', 'update' => 'RESTRICT']
            )
            ->create();

        $this->table('keycloak_sso_transactions')
            ->addColumn('crypto_request_id', 'uuid', [
                'after' => 'link_identity_ciphertext',
                'default' => null,
                'null' => true,
                'encoding' => 'ascii',
                'collation' => 'ascii_general_ci',
            ])
            ->addIndex(['crypto_request_id'], ['name' => 'idx_keycloak_sso_transactions_crypto_request'])
            ->addForeignKey('crypto_request_id', 'keycloak_sso_crypto_requests', 'id', [
                'delete' => 'CASCADE',
                'update' => 'RESTRICT',
            ])
            ->update();
    }
}
