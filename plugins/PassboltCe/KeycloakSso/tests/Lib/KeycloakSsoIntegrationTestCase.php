<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\Lib;

use App\Test\Lib\AppIntegrationTestCase;
use Cake\Core\Configure;
use Passbolt\Edition\Model\Dto\EditionDto;
use Passbolt\Edition\Service\EditionManager;
use Passbolt\Edition\Test\Lib\TestingEditionManager;
use Passbolt\KeycloakSso\Configuration\KeycloakSsoEnvironment;
use Passbolt\KeycloakSso\KeycloakSsoPlugin;

abstract class KeycloakSsoIntegrationTestCase extends AppIntegrationTestCase
{
    private string|false $previousEnabledEnvironment;
    private EditionManager $previousEditionManager;

    public function setUp(): void
    {
        $this->previousEnabledEnvironment = getenv(KeycloakSsoEnvironment::ENABLED);
        $this->previousEditionManager = EditionManager::getInstance();
        putenv(KeycloakSsoEnvironment::ENABLED . '=true');
        Configure::write('passbolt.edition', EditionDto::EDITION_CE);
        EditionManager::setInstance(new TestingEditionManager());
        $this->enableFeaturePlugin(KeycloakSsoPlugin::class);
        parent::setUp();
        $this->enableFeaturePlugin(KeycloakSsoPlugin::class);
    }

    public function tearDown(): void
    {
        if ($this->previousEnabledEnvironment === false) {
            putenv(KeycloakSsoEnvironment::ENABLED);
        } else {
            putenv(KeycloakSsoEnvironment::ENABLED . '=' . $this->previousEnabledEnvironment);
        }
        EditionManager::setInstance($this->previousEditionManager);
        parent::tearDown();
    }
}
