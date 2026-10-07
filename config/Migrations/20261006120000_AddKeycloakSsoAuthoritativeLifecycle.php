<?php
declare(strict_types=1);

use Migrations\AbstractMigration;

final class AddKeycloakSsoAuthoritativeLifecycle extends AbstractMigration
{
    /** Add fail-closed lifecycle state without changing core authentication tables. */
    public function change(): void
    {
        $ascii = ['encoding' => 'ascii', 'collation' => 'ascii_general_ci'];

        $this->table('keycloak_sso_provisioned_users')
            ->addColumn('lifecycle_status', 'string', [
                'limit' => 32,
                'null' => false,
                'default' => 'active',
            ] + $ascii)
            ->addColumn('last_seen', 'datetime', ['null' => true, 'default' => null])
            ->addColumn('last_checked', 'datetime', ['null' => true, 'default' => null])
            ->addColumn('absent_since', 'datetime', ['null' => true, 'default' => null])
            ->addColumn('deprovisioned_at', 'datetime', ['null' => true, 'default' => null])
            ->addColumn('deletion_eligible_at', 'datetime', ['null' => true, 'default' => null])
            ->addColumn('deprovision_reason', 'string', [
                'limit' => 32,
                'null' => true,
                'default' => null,
            ] + $ascii)
            ->addIndex(
                ['issuer', 'lifecycle_status', 'deletion_eligible_at'],
                ['name' => 'idx_keycloak_provisioned_user_lifecycle']
            )
            ->update();

        $this->table('keycloak_sso_group_memberships')
            ->addColumn('revoked', 'datetime', ['null' => true, 'default' => null])
            ->update();
    }
}
