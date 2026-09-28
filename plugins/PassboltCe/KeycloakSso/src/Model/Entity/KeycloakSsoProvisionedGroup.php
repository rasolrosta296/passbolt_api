<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Model\Entity;

use Cake\ORM\Entity;

/**
 * @property string $id
 * @property string $group_id
 * @property string $issuer
 * @property string $keycloak_group_id
 * @property string $keycloak_group_path
 */
final class KeycloakSsoProvisionedGroup extends Entity
{
    protected array $_accessible = ['*' => false];

    protected array $_hidden = [
        'keycloak_group_id',
    ];
}
