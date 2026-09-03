<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Oidc;

interface OidcResultConsumerInterface
{
    /**
     * Atomically consume a one-time result handle.
     */
    public function consumeResult(string $resultToken): void;
}
