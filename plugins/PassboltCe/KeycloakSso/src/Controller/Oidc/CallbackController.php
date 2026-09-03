<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Controller\Oidc;

use App\Controller\AppController;
use App\Middleware\ContainerInjectorMiddleware;
use Cake\Event\EventInterface;
use Passbolt\KeycloakSso\Error\Exception\OidcConfigurationException;
use Passbolt\KeycloakSso\Error\Exception\OidcNetworkException;
use Passbolt\KeycloakSso\Error\Exception\OidcTransactionException;
use Passbolt\KeycloakSso\Error\Exception\OidcValidationException;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction;
use Passbolt\KeycloakSso\Service\Audit\OidcAuditService;
use Passbolt\KeycloakSso\Service\Oidc\OidcCookieService;
use Passbolt\KeycloakSso\Service\Oidc\OidcServiceFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Throwable;

final class CallbackController extends AppController
{
    /**
     * @inheritDoc
     */
    public function beforeFilter(EventInterface $event)
    {
        $this->Authentication->allowUnauthenticated(['callback']);

        parent::beforeFilter($event);
    }

    /**
     * Consume the GET callback without creating Passbolt authentication state.
     */
    public function callback(): ResponseInterface
    {
        $audit = new OidcAuditService();
        try {
            $state = $this->scalarQuery('state');
            $binding = $this->getRequest()->getCookie(OidcCookieService::BROWSER_BINDING_COOKIE);
            if (!is_string($binding)) {
                throw new OidcValidationException('missing_browser_binding');
            }
            $callback = $this->serviceFactory()->callback();
            if ($this->getRequest()->getQuery('error') !== null) {
                $callback->failProviderResponse($state, $binding);
                throw new OidcValidationException('provider_returned_error');
            }
            $codeValue = $this->getRequest()->getQuery('code');
            $code = is_string($codeValue) ? $codeValue : '';

            $result = $callback->process($state, $binding, $code);
            if ($result->purpose === KeycloakSsoTransaction::PURPOSE_IDENTITY_PROOF) {
                $cookie = OidcCookieService::result($result->token);
                $resultRoute = '/auth/keycloak/result.json';
            } elseif ($result->purpose === KeycloakSsoTransaction::PURPOSE_IDENTITY_LINK) {
                $cookie = OidcCookieService::linkResult($result->token);
                $resultRoute = '/auth/keycloak/link/confirm';
            } else {
                throw new OidcValidationException('invalid_transaction_purpose');
            }
            $this->setResponse(
                $this->getResponse()
                    ->withCookie($cookie)
                    ->withExpiredCookie(OidcCookieService::expired(OidcCookieService::BROWSER_BINDING_COOKIE))
                    ->withHeader('Cache-Control', 'no-store')
                    ->withHeader('Pragma', 'no-cache')
            );
            $audit->success();
            $this->redirect($resultRoute, 303);

            return $this->getResponse();
        } catch (Throwable $exception) {
            $audit->failure($this->failureCategory($exception));
            $this->setResponse(
                $this->getResponse()
                    ->withExpiredCookie(OidcCookieService::expired(OidcCookieService::BROWSER_BINDING_COOKIE))
                    ->withHeader('Cache-Control', 'no-store')
                    ->withHeader('Pragma', 'no-cache')
            );
            $this->redirect('/auth/keycloak/error.json', 303);

            return $this->getResponse();
        }
    }

    /**
     * Read a scalar callback parameter without coercion.
     */
    private function scalarQuery(string $name): string
    {
        $value = $this->getRequest()->getQuery($name);
        if (!is_string($value)) {
            throw new OidcValidationException('malformed_callback');
        }

        return $value;
    }

    /**
     * Reduce failures to an allowlisted audit category.
     */
    private function failureCategory(Throwable $exception): string
    {
        return match (true) {
            $exception instanceof OidcConfigurationException => 'configuration',
            $exception instanceof OidcNetworkException => 'provider_unavailable',
            $exception instanceof OidcTransactionException => 'transaction_validation',
            $exception instanceof OidcValidationException &&
                $exception->reasonCode() === 'existing_user_not_unique' => 'user_discovery',
            $exception instanceof OidcValidationException => 'protocol_validation',
            default => 'unexpected_failure',
        };
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
