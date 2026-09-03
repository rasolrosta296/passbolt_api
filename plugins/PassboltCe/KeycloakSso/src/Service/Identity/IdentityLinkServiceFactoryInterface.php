<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Identity;

interface IdentityLinkServiceFactoryInterface
{
    /** Build purpose-bound authorization requests. */
    public function authorizationRequest(): IdentityLinkAuthorizationRequestService;

    /** Build the atomic confirmation service. */
    public function confirmer(): ConfirmIdentityLinkService;

    /** Build the current-user unlink service. */
    public function unlinker(): UnlinkIdentityService;

    /** Build the Passbolt server-session verifier. */
    public function sessions(): AuthenticatedPassboltSessionService;
}
