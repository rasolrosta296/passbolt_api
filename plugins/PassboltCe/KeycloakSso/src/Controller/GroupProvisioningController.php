<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Controller;

use App\Controller\AppController;
use Cake\Http\Exception\NotFoundException;
use Passbolt\KeycloakSso\Configuration\GroupProvisioningConfigurationService;
use Passbolt\KeycloakSso\Service\Identity\AuthenticatedPassboltSessionService;
use Passbolt\KeycloakSso\Service\Provisioning\GroupProvisioningQueueService;

final class GroupProvisioningController extends AppController
{
    /** Return pending work visible to the current Passbolt group manager. */
    public function pending(): void
    {
        $this->assertJson();
        $this->assertFeatureEnabled();
        $userId = $this->activeUserId();
        $this->noStore();
        $this->success(__('Pending Keycloak group provisioning requests.'), [
            'items' => (new GroupProvisioningQueueService())->pendingForManager($userId),
        ]);
    }

    /** Confirm that the unchanged Passbolt group-update flow completed one item. */
    public function complete(string $membershipId): void
    {
        $this->assertJson();
        $this->assertFeatureEnabled();
        $userId = $this->activeUserId();
        (new GroupProvisioningQueueService())->complete($membershipId, $userId);
        $this->noStore();
        $this->success(__('The Keycloak group provisioning request was completed.'));
    }

    /** Require the unchanged Passbolt authentication session and an active user. */
    private function activeUserId(): string
    {
        return (new AuthenticatedPassboltSessionService())
            ->getActiveUser($this->getRequest(), $this->User->id())
            ->id;
    }

    /** Hide this optional API when its independent feature gate is disabled. */
    private function assertFeatureEnabled(): void
    {
        if (!(new GroupProvisioningConfigurationService())->isEnabled()) {
            throw new NotFoundException(__('Page not found.'));
        }
    }

    /** Prevent caching of manager work-queue responses. */
    private function noStore(): void
    {
        $this->setResponse($this->getResponse()
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache'));
    }
}
