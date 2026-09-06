<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Controller;

use App\Controller\AppController;
use App\Middleware\ContainerInjectorMiddleware;
use Cake\Http\Exception\BadRequestException;
use Passbolt\KeycloakSso\Error\Exception\IdentityLinkException;
use Passbolt\KeycloakSso\Service\Audit\IdentityLinkAuditService;
use Passbolt\KeycloakSso\Service\Http\ConfiguredIssuerFormActionService;
use Passbolt\KeycloakSso\Service\Identity\IdentityLinkServiceFactoryInterface;
use Passbolt\KeycloakSso\Service\Oidc\OidcCookieService;
use Psr\Http\Message\ResponseInterface;
use Throwable;

final class IdentityLinkController extends AppController
{
    /**
     * Render a CSRF-protected, authenticated link initiation page.
     */
    public function index(): void
    {
        $this->activeSessionUserId();
        $this->allowConfiguredIssuerFormAction();
        $this->noStore();
        $this->set('csrfToken', (string)$this->getRequest()->getAttribute('csrfToken'));
        $this->viewBuilder()
            ->setLayout('default')
            ->setTemplatePath('IdentityLink')
            ->setTemplate('index');
    }

    /**
     * Begin a new identity-link OIDC transaction for the current Passbolt user.
     */
    public function start(): ResponseInterface
    {
        $userId = $this->activeSessionUserId();
        $this->allowConfiguredIssuerFormAction();
        $audit = new IdentityLinkAuditService();
        try {
            $audit->linkStarted($userId);
            $request = $this->factory()->authorizationRequest()->create($userId);
            $this->setResponse(
                $this->getResponse()
                    ->withCookie(OidcCookieService::browserBinding($request->browserBinding))
                    ->withHeader('Cache-Control', 'no-store')
                    ->withHeader('Pragma', 'no-cache')
            );
            $this->redirect($request->url, 303);

            return $this->getResponse();
        } catch (Throwable $exception) {
            $audit->linkFailed($userId, 'unexpected_failure');
            throw $exception;
        }
    }

    /**
     * Render explicit confirmation after a fresh, purpose-bound OIDC callback.
     */
    public function confirm(): void
    {
        $this->activeSessionUserId();
        $this->validatedLinkResultToken();
        $this->noStore();
        $this->set('csrfToken', (string)$this->getRequest()->getAttribute('csrfToken'));
        $this->viewBuilder()
            ->setLayout('default')
            ->setTemplatePath('IdentityLink')
            ->setTemplate('confirm');
    }

    /**
     * Atomically consume the fresh proof after explicit user confirmation.
     */
    public function confirmPost(): void
    {
        $userId = $this->activeSessionUserId();
        $this->requireConfirmation('link_keycloak_identity');
        $token = $this->validatedLinkResultToken();
        try {
            $this->factory()->confirmer()->confirm($token, $userId);
            $this->setResponse(
                $this->getResponse()->withExpiredCookie(
                    OidcCookieService::expired(OidcCookieService::LINK_RESULT_COOKIE)
                )
            );
            $this->noStore();
            $this->success(
                __('The Keycloak identity was linked. Passbolt cryptographic authentication remains required.')
            );
        } catch (Throwable) {
            $this->setResponse(
                $this->getResponse()->withExpiredCookie(
                    OidcCookieService::expired(OidcCookieService::LINK_RESULT_COOKIE)
                )
            );
            $this->noStore();
            $this->error(__('The Keycloak identity could not be linked.'));
        }
    }

    /**
     * Unlink only the current authenticated user's configured-provider identity.
     */
    public function unlink(): void
    {
        $userId = $this->activeSessionUserId();
        $this->requireConfirmation('unlink_keycloak_identity');
        try {
            $clientEnrollmentIds = $this->factory()->unlinker()->unlink($userId);
            $this->noStore();
            $this->success(__('The Keycloak identity was unlinked. Normal Passbolt login remains available.'), [
                'client_enrollment_uuids' => $clientEnrollmentIds,
            ]);
        } catch (IdentityLinkException) {
            $this->noStore();
            $this->error(__('The Keycloak identity could not be unlinked.'));
        }
    }

    /** Require and return the current active server-session user ID. */
    private function activeSessionUserId(): string
    {
        $user = $this->factory()->sessions()->getActiveUser($this->getRequest(), $this->User->id());

        return $user->id;
    }

    /** Read a syntactically valid one-time result handle from its HttpOnly cookie. */
    private function validatedLinkResultToken(): string
    {
        $token = $this->getRequest()->getCookie(OidcCookieService::LINK_RESULT_COOKIE);
        if (!is_string($token) || !preg_match('/^[A-Za-z0-9_-]{43}$/', $token)) {
            throw new BadRequestException(__('The Keycloak identity-link result is invalid or expired.'));
        }

        return $token;
    }

    /** Require an exact, server-defined confirmation value. */
    private function requireConfirmation(string $expected): void
    {
        $confirmation = $this->getRequest()->getData('confirmation');
        if (!is_string($confirmation) || !hash_equals($expected, $confirmation)) {
            throw new BadRequestException(__('Explicit confirmation is required.'));
        }
    }

    /** Prevent storage of all link and unlink responses. */
    private function noStore(): void
    {
        $this->setResponse(
            $this->getResponse()
                ->withHeader('Cache-Control', 'no-store')
                ->withHeader('Pragma', 'no-cache')
        );
    }

    /** Permit the strictly configured issuer origin only on link initiation. */
    private function allowConfiguredIssuerFormAction(): void
    {
        (new ConfiguredIssuerFormActionService())->allow($this->getRequest());
    }

    /** Resolve the plugin-isolated identity service factory. */
    private function factory(): IdentityLinkServiceFactoryInterface
    {
        /** @var \Cake\Core\ContainerInterface $container */
        $container = $this->getRequest()->getAttribute(ContainerInjectorMiddleware::CONTAINER_ATTRIBUTE);

        return $container->get(IdentityLinkServiceFactoryInterface::class);
    }
}
