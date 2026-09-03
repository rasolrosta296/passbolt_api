<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Controller\Oidc;

use App\Controller\AppController;
use Cake\Event\EventInterface;
use Cake\Http\Cookie\Cookie;
use Cake\I18n\DateTime;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;
use Passbolt\KeycloakSso\Service\Oidc\OidcServiceFactory;
use Psr\Http\Message\ResponseInterface;

final class AuthorizationController extends AppController
{
    public const BROWSER_BINDING_COOKIE = '__Host-passbolt_keycloak_binding';

    public function beforeFilter(EventInterface $event)
    {
        $this->Authentication->allowUnauthenticated(['index', 'start']);

        return parent::beforeFilter($event);
    }

    public function index(): void
    {
        $this->viewBuilder()
            ->setLayout('default')
            ->setTemplatePath('Oidc/Authorization')
            ->setTemplate('index');
    }

    public function start(): ResponseInterface
    {
        $request = (new OidcServiceFactory())->authorizationRequest()->create();
        $cookie = (new Cookie(self::BROWSER_BINDING_COOKIE))
            ->withValue($request->browserBinding)
            ->withPath('/')
            ->withSecure(true)
            ->withHttpOnly(true)
            ->withSameSite(Cookie::SAMESITE_LAX)
            ->withExpiry(DateTime::now()->addSeconds(OidcConfigurationDto::TRANSACTION_TTL_SECONDS));
        $this->setResponse($this->getResponse()->withCookie($cookie));

        return $this->redirect($request->url, 303);
    }
}
