<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Recovery;

interface AccountRecoveryServiceFactoryInterface
{
    /** Build the purpose-bound authorization service. */
    public function authorization(): AccountRecoveryAuthorizationService;

    /** Build the one-time recovery-result consumer. */
    public function results(): AccountRecoveryResultService;
}
