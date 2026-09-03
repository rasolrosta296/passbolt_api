<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Oidc;

use Passbolt\KeycloakSso\Configuration\OidcConfigurationService;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;
use Passbolt\KeycloakSso\Service\Transaction\CreateOidcTransactionService;
use Passbolt\KeycloakSso\Service\Transaction\TransactionSecretProtector;
use Passbolt\KeycloakSso\Utility\Http\SafeOidcHttpClient;

final class OidcServiceFactory
{
    private ?OidcConfigurationDto $configuration = null;

    public function configuration(): OidcConfigurationDto
    {
        return $this->configuration ??= (new OidcConfigurationService())->load();
    }

    public function authorizationRequest(): AuthorizationRequestService
    {
        $configuration = $this->configuration();
        $httpClient = new SafeOidcHttpClient($configuration);
        $cache = new OidcMetadataCache();
        $discovery = new OidcDiscoveryService($configuration, $httpClient, $cache);
        $protector = new TransactionSecretProtector($configuration->transactionEncryptionKey);

        return new AuthorizationRequestService(
            $configuration,
            $discovery,
            new CreateOidcTransactionService($protector)
        );
    }
}
