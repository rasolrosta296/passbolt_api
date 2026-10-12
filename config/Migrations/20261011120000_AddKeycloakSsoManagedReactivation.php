<?php
declare(strict_types=1);

use Migrations\AbstractMigration;

final class AddKeycloakSsoManagedReactivation extends AbstractMigration
{
    /** Record exact plugin-owned suspensions without adopting existing disabled accounts. */
    public function change(): void
    {
        $this->table('keycloak_sso_provisioned_users')
            ->addColumn('managed_disabled_at', 'datetime', [
                'null' => true,
                'default' => null,
            ])
            ->update();
    }
}
