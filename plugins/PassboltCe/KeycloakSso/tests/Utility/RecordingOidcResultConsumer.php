<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\Utility;

use Passbolt\KeycloakSso\Service\Oidc\OidcResultConsumerInterface;

final class RecordingOidcResultConsumer implements OidcResultConsumerInterface
{
    public ?string $consumedToken = null;

    public function consumeResult(string $resultToken): void
    {
        $this->consumedToken = $resultToken;
    }
}
