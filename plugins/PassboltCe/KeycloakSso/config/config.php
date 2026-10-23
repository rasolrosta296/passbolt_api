<?php
declare(strict_types=1);

use Passbolt\KeycloakSso\Configuration\KeycloakSsoEnvironment;

return [
    'passbolt' => [
        'plugins' => [
            'keycloakSso' => [
                'version' => '1.0.0',
                'enabled' => KeycloakSsoEnvironment::isEnabled(),
                'accountRecoveryEnabled' => KeycloakSsoEnvironment::isAccountRecoveryEnabled(),
                'settingsVisibility' => [
                    'whiteListPublic' => ['enabled', 'accountRecoveryEnabled'],
                ],
            ],
        ],
    ],
];
