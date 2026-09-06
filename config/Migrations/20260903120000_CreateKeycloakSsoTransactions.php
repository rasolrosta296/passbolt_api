<?php
declare(strict_types=1);

use Migrations\AbstractMigration;

final class CreateKeycloakSsoTransactions extends AbstractMigration
{
    /**
     * Create the short-lived OIDC transaction table.
     */
    public function change(): void
    {
        $this->table('keycloak_sso_transactions', [
            'id' => false,
            'primary_key' => ['id'],
            'encoding' => 'ascii',
            'collation' => 'ascii_general_ci',
        ])
            ->addColumn('id', 'uuid', [
                'null' => false,
                'encoding' => 'ascii',
                'collation' => 'ascii_general_ci',
            ])
            ->addColumn('state_hash', 'char', [
                'limit' => 64,
                'null' => false,
                'encoding' => 'ascii',
                'collation' => 'ascii_bin',
            ])
            ->addColumn('nonce_hash', 'char', [
                'limit' => 64,
                'null' => false,
                'encoding' => 'ascii',
                'collation' => 'ascii_bin',
            ])
            ->addColumn('browser_binding_hash', 'char', [
                'limit' => 64,
                'null' => false,
                'encoding' => 'ascii',
                'collation' => 'ascii_bin',
            ])
            ->addColumn('pkce_verifier_ciphertext', 'text', ['null' => true])
            ->addColumn('configuration_hash', 'char', [
                'limit' => 64,
                'null' => false,
                'encoding' => 'ascii',
                'collation' => 'ascii_bin',
            ])
            ->addColumn('issuer', 'string', ['limit' => 255, 'null' => false])
            ->addColumn('client_id', 'string', [
                'limit' => 255,
                'null' => false,
                'encoding' => 'ascii',
                'collation' => 'ascii_general_ci',
            ])
            ->addColumn('redirect_uri', 'text', ['null' => false])
            ->addColumn('status', 'string', [
                'limit' => 32,
                'null' => false,
                'encoding' => 'ascii',
                'collation' => 'ascii_general_ci',
            ])
            ->addColumn('result_token_hash', 'char', [
                'limit' => 64,
                'null' => true,
                'encoding' => 'ascii',
                'collation' => 'ascii_bin',
            ])
            ->addColumn('failure_code', 'string', [
                'limit' => 64,
                'null' => true,
                'encoding' => 'ascii',
                'collation' => 'ascii_bin',
            ])
            ->addColumn('expires', 'datetime', ['null' => false])
            ->addColumn('result_expires', 'datetime', ['null' => true])
            ->addColumn('created', 'datetime', ['null' => false])
            ->addColumn('modified', 'datetime', ['null' => false])
            ->addIndex(['state_hash'], ['unique' => true])
            ->addIndex(['result_token_hash'], ['unique' => true])
            ->addIndex(['status', 'expires'])
            ->create();
    }
}
