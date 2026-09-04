<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Controller;

use App\Controller\AppController;
use App\Middleware\ContainerInjectorMiddleware;
use Cake\Event\EventInterface;
use Cake\Http\Exception\BadRequestException;
use Passbolt\KeycloakSso\Cryptography\Protocol\CborProtocolV1;
use Passbolt\KeycloakSso\Error\Exception\CryptoSsoException;
use Passbolt\KeycloakSso\Service\Audit\CryptoSsoAuditService;
use Passbolt\KeycloakSso\Service\Crypto\CryptoSsoServiceFactoryInterface;
use Passbolt\KeycloakSso\Service\Oidc\OidcCookieService;
use Throwable;

final class CryptoSsoController extends AppController
{
    /**
     * Configure unauthenticated cryptographic SSO actions.
     */
    public function beforeFilter(EventInterface $event)
    {
        $this->Authentication->allowUnauthenticated(['startLogin', 'release', 'complete']);
        parent::beforeFilter($event);
    }

    /**
     * Start a fresh authenticated enrollment OIDC transaction.
     */
    public function startEnrollment(): void
    {
        $userId = $this->activeUserId();
        $audit = new CryptoSsoAuditService();
        try {
            $request = $this->factory()->authorization()->startEnrollment($userId);
            $cookie = OidcCookieService::browserBinding($request->browserBinding);
            $this->setResponse($this->getResponse()->withCookie($cookie));
            $this->noStore();
            $audit->record('enrollment_started', $userId);
            $this->success(__('Keycloak cryptographic enrollment authentication started.'), [
                'authorization_url' => $request->url,
                'enrollment_id' => $request->enrollmentId,
                'identity_id' => $request->identityId,
                'protocol_version' => CborProtocolV1::VERSION,
                'crypto_suite' => CborProtocolV1::SUITE,
            ]);
        } catch (Throwable $exception) {
            $audit->record('enrollment_failed', $userId, 'unexpected');
            throw $exception;
        }
    }

    /**
     * Persist a browser-profile enrollment after all proofs validate.
     */
    public function enroll(): void
    {
        $userId = $this->activeUserId();
        $token = $this->cookie(OidcCookieService::CRYPTO_RESULT_COOKIE);
        $audit = new CryptoSsoAuditService();
        try {
            $input = (array)$this->getRequest()->getData();
            $enrollment = $this->factory()->enrollment()->enroll($token, $userId, $input);
            $this->expireCryptoResult();
            $this->noStore();
            $audit->record('enrollment_succeeded', $userId);
            $this->success(__('The browser-profile enrollment was created.'), [
                'enrollment_id' => $enrollment->id,
                'client_enrollment_uuid' => $enrollment->client_enrollment_uuid,
            ]);
        } catch (Throwable $exception) {
            $this->expireCryptoResult();
            $this->noStore();
            $audit->record('enrollment_failed', $userId, $this->category($exception));
            throw $exception;
        }
    }

    /**
     * Start a signed, purpose-bound cryptographic release transaction.
     */
    public function startLogin(): void
    {
        $audit = new CryptoSsoAuditService();
        try {
            $request = $this->factory()->authorization()->startRelease((array)$this->getRequest()->getData());
            $cookie = OidcCookieService::browserBinding($request->browserBinding);
            $this->setResponse($this->getResponse()->withCookie($cookie));
            $this->noStore();
            $audit->record('release_started');
            $this->success(__('Keycloak cryptographic release authentication started.'), [
                'authorization_url' => $request->url,
                'request_id' => $request->requestId,
            ]);
        } catch (Throwable $exception) {
            $audit->record('release_failed', null, $this->category($exception));
            throw $exception;
        }
    }

    /**
     * Atomically release an HPKE-sealed server share.
     */
    public function release(): void
    {
        $token = $this->cookie(OidcCookieService::CRYPTO_RESULT_COOKIE);
        $audit = new CryptoSsoAuditService();
        try {
            $package = $this->factory()->release()->release($token, (array)$this->getRequest()->getData());
            $this->expireCryptoResult();
            $this->noStore();
            $audit->record('release_succeeded');
            $this->success(__('The one-time encrypted server share was released.'), $package);
        } catch (Throwable $exception) {
            $this->expireCryptoResult();
            $this->noStore();
            $audit->record('release_failed', null, $this->category($exception));
            throw $exception;
        }
    }

    /**
     * Render the fixed OIDC completion page.
     */
    public function complete(): void
    {
        $this->noStore();
        $this->set('message', __('Return to the Passbolt extension to continue cryptographic authentication.'));
        $this->viewBuilder()->setLayout('default')->setTemplatePath('CryptoSso')->setTemplate('complete');
    }

    /**
     * Return the normally authenticated Passbolt user's UUID.
     */
    private function activeUserId(): string
    {
        return $this->factory()->sessions()->getActiveUser($this->getRequest(), $this->User->id())->id;
    }

    /**
     * Read and validate a one-time capability cookie.
     */
    private function cookie(string $name): string
    {
        $value = $this->getRequest()->getCookie($name);
        if (!is_string($value) || preg_match('/^[A-Za-z0-9_-]{43}$/D', $value) !== 1) {
            throw new BadRequestException(__('The one-time cryptographic SSO capability is invalid.'));
        }

        return $value;
    }

    /**
     * Expire the one-time cryptographic result cookie.
     */
    private function expireCryptoResult(): void
    {
        $this->setResponse($this->getResponse()->withExpiredCookie(
            OidcCookieService::expired(OidcCookieService::CRYPTO_RESULT_COOKIE)
        ));
    }

    /**
     * Prevent storage of cryptographic flow responses.
     */
    private function noStore(): void
    {
        $response = $this->getResponse()
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache');
        $this->setResponse($response);
    }

    /**
     * Map an internal failure to a non-sensitive audit category.
     */
    private function category(Throwable $exception): string
    {
        if (!($exception instanceof CryptoSsoException)) {
            return 'unexpected';
        }

        return match (true) {
            str_contains($exception->reasonCode(), 'identity'),
            str_contains($exception->reasonCode(), 'owner') => 'identity',
            str_contains($exception->reasonCode(), 'signature'),
            str_contains($exception->reasonCode(), 'share'),
            str_contains($exception->reasonCode(), 'hpke') => 'cryptography',
            str_contains($exception->reasonCode(), 'replay'),
            str_contains($exception->reasonCode(), 'capability') => 'protocol',
            default => 'protocol',
        };
    }

    /**
     * Resolve the plugin-owned cryptographic SSO service factory.
     */
    private function factory(): CryptoSsoServiceFactoryInterface
    {
        /** @var \Cake\Core\ContainerInterface $container */
        $container = $this->getRequest()->getAttribute(ContainerInjectorMiddleware::CONTAINER_ATTRIBUTE);

        return $container->get(CryptoSsoServiceFactoryInterface::class);
    }
}
