<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Controller\Oidc;

use App\Controller\AppController;
use App\Middleware\ContainerInjectorMiddleware;
use App\Middleware\ContentSecurityPolicyExtension;
use App\Middleware\ContentSecurityPolicyMiddleware;
use Cake\Event\EventInterface;
use Cake\Http\Exception\InternalErrorException;
use Passbolt\KeycloakSso\Configuration\OidcConfigurationService;
use Passbolt\KeycloakSso\Service\Oidc\OidcCookieService;
use Passbolt\KeycloakSso\Service\Oidc\OidcServiceFactoryInterface;
use Psr\Http\Message\ResponseInterface;

final class AuthorizationController extends AppController
{
    /**
     * @inheritDoc
     */
    public function beforeFilter(EventInterface $event)
    {
        $this->Authentication->allowUnauthenticated(['index', 'start']);

        parent::beforeFilter($event);
    }

    /**
     * Render the CSRF-protected login initiation form.
     */
    public function index(): void
    {
        $this->allowConfiguredIssuerFormAction();
        $this->set('csrfToken', (string)$this->getRequest()->getAttribute('csrfToken'));
        $this->viewBuilder()
            ->setLayout('default')
            ->setTemplatePath('Oidc/Authorization')
            ->setTemplate('index');
    }

    /**
     * Create a browser-bound transaction and redirect to the trusted provider.
     */
    public function start(): ResponseInterface
    {
        $this->allowConfiguredIssuerFormAction();
        $request = $this->serviceFactory()->authorizationRequest()->create();
        $cookie = OidcCookieService::browserBinding($request->browserBinding);
        $this->setResponse(
            $this->getResponse()
                ->withCookie($cookie)
                ->withHeader('Cache-Control', 'no-store')
                ->withHeader('Pragma', 'no-cache')
        );
        $this->redirect($request->url, 303);

        return $this->getResponse();
    }

    /**
     * Permit only the strictly configured issuer origin on this initiation response.
     */
    private function allowConfiguredIssuerFormAction(): void
    {
        $configurationService = new OidcConfigurationService();
        $configuration = $configurationService->load();
        $extension = $this->getRequest()->getAttribute(ContentSecurityPolicyMiddleware::EXTENSION_ATTRIBUTE);
        if (!$extension instanceof ContentSecurityPolicyExtension) {
            throw new InternalErrorException('The request-scoped CSP extension is unavailable.');
        }

        $extension->addFormActionOrigin($configurationService->issuerOrigin($configuration->issuer));
    }

    /**
     * Resolve the plugin's isolated service factory.
     */
    private function serviceFactory(): OidcServiceFactoryInterface
    {
        /** @var \Cake\Core\ContainerInterface $container */
        $container = $this->getRequest()->getAttribute(ContainerInjectorMiddleware::CONTAINER_ATTRIBUTE);

        return $container->get(OidcServiceFactoryInterface::class);
    }
}
