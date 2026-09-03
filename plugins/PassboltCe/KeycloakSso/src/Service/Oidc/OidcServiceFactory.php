<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Oidc;

use Passbolt\KeycloakSso\Configuration\OidcConfigurationService;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;
use Passbolt\KeycloakSso\Service\Audit\IdentityLinkAuditService;
use Passbolt\KeycloakSso\Service\Identity\ExistingUserDiscoveryService;
use Passbolt\KeycloakSso\Service\Identity\IdentityLinkPersistenceService;
use Passbolt\KeycloakSso\Service\Identity\IdentityLinkProofProtector;
use Passbolt\KeycloakSso\Service\Identity\PrepareIdentityLinkService;
use Passbolt\KeycloakSso\Service\Transaction\ClaimOidcTransactionService;
use Passbolt\KeycloakSso\Service\Transaction\CreateOidcTransactionService;
use Passbolt\KeycloakSso\Service\Transaction\TransactionSecretProtector;
use Passbolt\KeycloakSso\Utility\Http\SafeOidcHttpClient;

final class OidcServiceFactory implements OidcServiceFactoryInterface
{
    private ?OidcConfigurationDto $configuration = null;

    /**
     * Load and memoize strict environment configuration.
     */
    public function configuration(): OidcConfigurationDto
    {
        return $this->configuration ??= (new OidcConfigurationService())->load();
    }

    /**
     * Build the authorization endpoint dependency graph.
     */
    public function authorizationRequest(): AuthorizationRequestProviderInterface
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

    /**
     * Build the callback validation dependency graph.
     */
    public function callback(): OidcCallbackProcessorInterface
    {
        $configuration = $this->configuration();
        $httpClient = new SafeOidcHttpClient($configuration);
        $cache = new OidcMetadataCache();
        $discovery = new OidcDiscoveryService($configuration, $httpClient, $cache);
        $jwks = new JwksProvider($configuration, $discovery, $httpClient, $cache);
        $protector = new TransactionSecretProtector($configuration->transactionEncryptionKey);

        $users = new ExistingUserDiscoveryService();
        $links = new IdentityLinkPersistenceService();

        return new OidcCallbackService(
            $configuration,
            new ClaimOidcTransactionService($protector),
            new AuthorizationCodeExchangeService($configuration, $discovery, $httpClient),
            new IdTokenValidationService($configuration, $jwks),
            $users,
            new PrepareIdentityLinkService(
                $users,
                $links,
                new IdentityLinkProofProtector($protector),
                new IdentityLinkAuditService()
            )
        );
    }

    /**
     * Build the one-time result consumer.
     */
    public function transactions(): OidcResultConsumerInterface
    {
        return new ClaimOidcTransactionService(
            new TransactionSecretProtector($this->configuration()->transactionEncryptionKey)
        );
    }
}
