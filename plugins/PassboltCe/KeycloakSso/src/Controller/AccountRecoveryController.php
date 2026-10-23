<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Controller;

use App\Controller\AppController;
use App\Middleware\ContainerInjectorMiddleware;
use App\Model\Entity\Role;
use Cake\Event\EventInterface;
use Cake\Http\Exception\BadRequestException;
use Cake\Http\Exception\ForbiddenException;
use Cake\Http\Exception\NotFoundException;
use Passbolt\KeycloakSso\Configuration\AccountRecoveryConfigurationService;
use Passbolt\KeycloakSso\Configuration\KeycloakSsoEnvironment;
use Passbolt\KeycloakSso\Service\Http\ConfiguredIssuerFormActionService;
use Passbolt\KeycloakSso\Service\Oidc\OidcCookieService;
use Passbolt\KeycloakSso\Service\Recovery\AccountRecoveryServiceFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Throwable;

final class AccountRecoveryController extends AppController
{
    /** @inheritDoc */
    public function beforeFilter(EventInterface $event)
    {
        $this->Authentication->allowUnauthenticated(['index', 'start', 'complete', 'failure']);

        parent::beforeFilter($event);
    }

    /** Render the CSRF-protected Keycloak recovery initiation page. */
    public function index(): void
    {
        $this->assertFeatureEnabled();
        $this->assertGuest();
        $this->allowConfiguredIssuerFormAction();
        $this->noStore();
        $this->set('csrfToken', (string)$this->getRequest()->getAttribute('csrfToken'));
        $this->viewBuilder()
            ->setLayout('default')
            ->setTemplatePath('AccountRecovery')
            ->setTemplate('index');
    }

    /** Start a fresh interactive Keycloak proof for normal Passbolt recovery. */
    public function start(): ResponseInterface
    {
        $this->assertFeatureEnabled();
        $this->assertGuest();
        $this->allowConfiguredIssuerFormAction();
        $request = $this->factory()->authorization()->create();
        $this->setResponse(
            $this->getResponse()
                ->withCookie(OidcCookieService::browserBinding($request->browserBinding))
                ->withHeader('Cache-Control', 'no-store')
                ->withHeader('Pragma', 'no-cache')
        );

        return $this->getResponse()
            ->withStatus(303)
            ->withHeader('Location', $request->url);
    }

    /** Consume the OIDC proof once and enter Passbolt's unchanged recovery flow. */
    public function complete(): ResponseInterface
    {
        $this->assertFeatureEnabled();
        $this->assertGuest();
        $resultToken = $this->getRequest()->getCookie(OidcCookieService::ACCOUNT_RECOVERY_RESULT_COOKIE);
        $this->expireResultCookie();
        $this->noStore();
        try {
            if (!is_string($resultToken)) {
                throw new BadRequestException('The Keycloak account-recovery result is missing.');
            }
            $grant = $this->factory()->results()->consume($resultToken);
            $location = sprintf('/setup/recover/start/%s/%s', $grant->userId, $grant->token);

            return $this->getResponse()->withStatus(303)->withHeader('Location', $location);
        } catch (Throwable) {
            return $this->getResponse()
                ->withStatus(303)
                ->withHeader('Location', '/auth/keycloak/recover/error');
        }
    }

    /** Render only a generic recovery failure. */
    public function failure(): void
    {
        $this->assertFeatureEnabled();
        $this->assertGuest();
        $this->expireResultCookie();
        $this->noStore();
        $this->viewBuilder()
            ->setLayout('default')
            ->setTemplatePath('AccountRecovery')
            ->setTemplate('failure');
    }

    /** Keep account recovery unavailable to an already authenticated browser. */
    private function assertGuest(): void
    {
        if ($this->User->role() !== Role::GUEST) {
            throw new ForbiddenException(__('Only guests are allowed to recover an account. Please logout first.'));
        }
    }

    /** Require the independent account-recovery gate and policy. */
    private function assertFeatureEnabled(): void
    {
        if (!KeycloakSsoEnvironment::isEnabled() || !KeycloakSsoEnvironment::isAccountRecoveryEnabled()) {
            throw new NotFoundException();
        }
        (new AccountRecoveryConfigurationService())->load();
    }

    /** Permit only the configured issuer origin on initiation responses. */
    private function allowConfiguredIssuerFormAction(): void
    {
        (new ConfiguredIssuerFormActionService())->allow($this->getRequest());
    }

    /** Prevent recovery responses from being stored. */
    private function noStore(): void
    {
        $this->setResponse(
            $this->getResponse()
                ->withHeader('Cache-Control', 'no-store')
                ->withHeader('Pragma', 'no-cache')
        );
    }

    /** Expire the one-time proof cookie on every terminal recovery response. */
    private function expireResultCookie(): void
    {
        $this->setResponse(
            $this->getResponse()->withExpiredCookie(
                OidcCookieService::expired(OidcCookieService::ACCOUNT_RECOVERY_RESULT_COOKIE)
            )
        );
    }

    /** Resolve the isolated account-recovery factory. */
    private function factory(): AccountRecoveryServiceFactoryInterface
    {
        /** @var \Cake\Core\ContainerInterface $container */
        $container = $this->getRequest()->getAttribute(ContainerInjectorMiddleware::CONTAINER_ATTRIBUTE);

        return $container->get(AccountRecoveryServiceFactoryInterface::class);
    }
}
