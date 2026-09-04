<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Crypto;

use Passbolt\KeycloakSso\Service\Identity\AuthenticatedPassboltSessionService;

interface CryptoSsoServiceFactoryInterface
{
    /** Return the OIDC authorization service. */
    public function authorization(): CryptoOidcAuthorizationService;

    /** Return the browser-profile enrollment service. */
    public function enrollment(): CryptoEnrollmentService;

    /** Return the one-time server-share release service. */
    public function release(): CryptoReleaseService;

    /** Return the current-user enrollment revocation service. */
    public function revocation(): RevokeCryptoEnrollmentsService;

    /** Return the unchanged Passbolt session inspection service. */
    public function sessions(): AuthenticatedPassboltSessionService;
}
