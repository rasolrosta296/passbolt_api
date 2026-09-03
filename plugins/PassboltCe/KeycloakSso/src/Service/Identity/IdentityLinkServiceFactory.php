<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Identity;

use Passbolt\KeycloakSso\Configuration\OidcConfigurationService;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;
use Passbolt\KeycloakSso\Service\Audit\IdentityLinkAuditService;
use Passbolt\KeycloakSso\Service\Oidc\OidcDiscoveryService;
use Passbolt\KeycloakSso\Service\Oidc\OidcMetadataCache;
use Passbolt\KeycloakSso\Service\Transaction\CreateOidcTransactionService;
use Passbolt\KeycloakSso\Service\Transaction\TransactionSecretProtector;
use Passbolt\KeycloakSso\Utility\Http\SafeOidcHttpClient;

final class IdentityLinkServiceFactory implements IdentityLinkServiceFactoryInterface
{
    private ?OidcConfigurationDto $configuration = null;

    /** Build purpose-bound authorization request dependencies. */
    public function authorizationRequest(): IdentityLinkAuthorizationRequestService
    {
        $configuration = $this->configuration();
        $protector = new TransactionSecretProtector($configuration->transactionEncryptionKey);

        return new IdentityLinkAuthorizationRequestService(
            $configuration,
            new OidcDiscoveryService(
                $configuration,
                new SafeOidcHttpClient($configuration),
                new OidcMetadataCache()
            ),
            new CreateOidcTransactionService($protector)
        );
    }

    /** Build atomic confirmation dependencies. */
    public function confirmer(): ConfirmIdentityLinkService
    {
        $configuration = $this->configuration();
        $users = new ExistingUserDiscoveryService();
        $links = new IdentityLinkPersistenceService();
        $protector = new IdentityLinkProofProtector(
            new TransactionSecretProtector($configuration->transactionEncryptionKey)
        );

        return new ConfirmIdentityLinkService(
            $configuration->issuer,
            $configuration->configurationHash(),
            $users,
            $links,
            $protector,
            new IdentityLinkAuditService()
        );
    }

    /** Build current-user unlink dependencies. */
    public function unlinker(): UnlinkIdentityService
    {
        return new UnlinkIdentityService($this->configuration()->issuer, new IdentityLinkAuditService());
    }

    /** Build the server-side Passbolt session verifier. */
    public function sessions(): AuthenticatedPassboltSessionService
    {
        return new AuthenticatedPassboltSessionService();
    }

    /** Load and memoize strict OIDC configuration. */
    private function configuration(): OidcConfigurationDto
    {
        return $this->configuration ??= (new OidcConfigurationService())->load();
    }
}
