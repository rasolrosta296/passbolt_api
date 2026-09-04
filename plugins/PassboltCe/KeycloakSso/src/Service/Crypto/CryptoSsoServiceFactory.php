<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Crypto;

use Passbolt\KeycloakSso\Configuration\CryptoConfigurationService;
use Passbolt\KeycloakSso\Configuration\OidcConfigurationService;
use Passbolt\KeycloakSso\Cryptography\HpkeReleaseService;
use Passbolt\KeycloakSso\Cryptography\OpenPgpEnrollmentProofVerifier;
use Passbolt\KeycloakSso\Cryptography\ProfileSigningKeyVerifier;
use Passbolt\KeycloakSso\Cryptography\ServerShareProtector;
use Passbolt\KeycloakSso\Model\Dto\CryptoConfigurationDto;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;
use Passbolt\KeycloakSso\Service\Identity\AuthenticatedPassboltSessionService;
use Passbolt\KeycloakSso\Service\Oidc\OidcDiscoveryService;
use Passbolt\KeycloakSso\Service\Oidc\OidcMetadataCache;
use Passbolt\KeycloakSso\Service\Transaction\CreateOidcTransactionService;
use Passbolt\KeycloakSso\Service\Transaction\TransactionSecretProtector;
use Passbolt\KeycloakSso\Utility\Http\SafeOidcHttpClient;

final class CryptoSsoServiceFactory implements CryptoSsoServiceFactoryInterface
{
    private ?OidcConfigurationDto $oidcConfiguration = null;
    private ?CryptoConfigurationDto $cryptoConfiguration = null;

    /**
     * Build the purpose-bound OIDC authorization service.
     */
    public function authorization(): CryptoOidcAuthorizationService
    {
        $oidc = $this->oidc();
        $protector = $this->transactionProtector();

        return new CryptoOidcAuthorizationService(
            $oidc,
            $this->crypto(),
            new OidcDiscoveryService($oidc, new SafeOidcHttpClient($oidc), new OidcMetadataCache()),
            new CreateOidcTransactionService($protector),
            $protector,
            new ProfileSigningKeyVerifier(),
            $this->rotationBarrier()
        );
    }

    /**
     * Build the cryptographic enrollment service.
     */
    public function enrollment(): CryptoEnrollmentService
    {
        $crypto = $this->crypto();

        return new CryptoEnrollmentService(
            $crypto,
            new CryptoResultClaimService(),
            new ProfileSigningKeyVerifier(),
            new OpenPgpEnrollmentProofVerifier(),
            new ServerShareProtector($crypto),
            $this->rotationBarrier()
        );
    }

    /**
     * Build the one-time server-share release service.
     */
    public function release(): CryptoReleaseService
    {
        return new CryptoReleaseService(
            new CryptoResultClaimService(),
            $this->transactionProtector(),
            new ServerShareProtector($this->crypto()),
            new HpkeReleaseService(),
            new ProfileSigningKeyVerifier(),
            $this->rotationBarrier()
        );
    }

    /** Build the server-authoritative passphrase-rotation barrier. */
    public function rotationBarrier(): RotationBarrierService
    {
        return new RotationBarrierService(
            $this->transactionProtector(),
            new RevokeCryptoEnrollmentsService()
        );
    }

    /**
     * Build the existing-session inspection service.
     */
    public function sessions(): AuthenticatedPassboltSessionService
    {
        return new AuthenticatedPassboltSessionService();
    }

    /**
     * Load and cache strict OIDC configuration.
     */
    private function oidc(): OidcConfigurationDto
    {
        return $this->oidcConfiguration ??= (new OidcConfigurationService())->load();
    }

    /**
     * Load and cache strict cryptographic SSO configuration.
     */
    private function crypto(): CryptoConfigurationDto
    {
        return $this->cryptoConfiguration ??= (new CryptoConfigurationService())->load();
    }

    /**
     * Build the transaction-secret protector.
     */
    private function transactionProtector(): TransactionSecretProtector
    {
        return new TransactionSecretProtector($this->oidc()->transactionEncryptionKey);
    }
}
