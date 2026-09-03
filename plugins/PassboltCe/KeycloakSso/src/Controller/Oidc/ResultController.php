<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Controller\Oidc;

use App\Controller\AppController;
use App\Middleware\ContainerInjectorMiddleware;
use Cake\Event\EventInterface;
use Passbolt\KeycloakSso\Error\Exception\OidcTransactionException;
use Passbolt\KeycloakSso\Service\Oidc\OidcCookieService;
use Passbolt\KeycloakSso\Service\Oidc\OidcServiceFactoryInterface;

final class ResultController extends AppController
{
    /**
     * @inheritDoc
     */
    public function beforeFilter(EventInterface $event)
    {
        $this->Authentication->allowUnauthenticated(['result', 'failure']);

        parent::beforeFilter($event);
    }

    /**
     * Consume and render the minimal one-time milestone result.
     */
    public function result(): void
    {
        $this->noStore();
        $token = $this->getRequest()->getCookie(OidcCookieService::RESULT_COOKIE);
        try {
            if (!is_string($token) || !preg_match('/^[A-Za-z0-9_-]{43}$/', $token)) {
                throw new OidcTransactionException('The OIDC result is invalid.');
            }
            $this->serviceFactory()->transactions()->consumeResult($token);
            $this->setResponse(
                $this->getResponse()->withExpiredCookie(OidcCookieService::expired(OidcCookieService::RESULT_COOKIE))
            );
            $this->success(__('Keycloak identity verification succeeded.'), [
                'oidc_authenticated' => true,
                'passbolt_user_exists' => true,
                'next_step' => 'passbolt_cryptographic_authentication_required',
            ]);
        } catch (OidcTransactionException) {
            $this->error(__('The Keycloak verification result is invalid or expired.'));
        }
    }

    /**
     * Render a generic non-sensitive callback failure.
     */
    public function failure(): void
    {
        $this->noStore();
        $this->error(__('Keycloak identity verification failed.'));
    }

    /**
     * Prevent storage of OIDC callback and result responses.
     */
    private function noStore(): void
    {
        $this->setResponse(
            $this->getResponse()
                ->withHeader('Cache-Control', 'no-store')
                ->withHeader('Pragma', 'no-cache')
        );
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
