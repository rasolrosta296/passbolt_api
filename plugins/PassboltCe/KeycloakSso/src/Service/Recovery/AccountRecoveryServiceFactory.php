<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Recovery;

use Passbolt\KeycloakSso\Configuration\AccountRecoveryConfigurationService;
use Passbolt\KeycloakSso\Configuration\OidcConfigurationService;
use Passbolt\KeycloakSso\Service\Oidc\OidcDiscoveryService;
use Passbolt\KeycloakSso\Service\Oidc\OidcMetadataCache;
use Passbolt\KeycloakSso\Service\Transaction\CreateOidcTransactionService;
use Passbolt\KeycloakSso\Service\Transaction\TransactionSecretProtector;
use Passbolt\KeycloakSso\Utility\Http\SafeOidcHttpClient;

final class AccountRecoveryServiceFactory implements AccountRecoveryServiceFactoryInterface
{
    /** @inheritDoc */
    public function authorization(): AccountRecoveryAuthorizationService
    {
        $oidc = (new OidcConfigurationService())->load();
        $recovery = (new AccountRecoveryConfigurationService())->load();
        $http = new SafeOidcHttpClient($oidc);
        $discovery = new OidcDiscoveryService($oidc, $http, new OidcMetadataCache());
        $protector = new TransactionSecretProtector($oidc->transactionEncryptionKey);

        return new AccountRecoveryAuthorizationService(
            $oidc,
            $recovery,
            $discovery,
            new CreateOidcTransactionService($protector)
        );
    }

    /** @inheritDoc */
    public function results(): AccountRecoveryResultService
    {
        $oidc = (new OidcConfigurationService())->load();
        $protector = new TransactionSecretProtector($oidc->transactionEncryptionKey);

        return new AccountRecoveryResultService(
            $oidc->issuer,
            $oidc->configurationHash(),
            new AccountRecoveryIdentityProofProtector($protector)
        );
    }
}
