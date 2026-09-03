<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Transaction;

use App\Utility\UuidFactory;
use Cake\I18n\DateTime;
use Cake\ORM\Locator\LocatorAwareTrait;
use Passbolt\KeycloakSso\Error\Exception\OidcTransactionException;
use Passbolt\KeycloakSso\Model\Dto\CreatedOidcTransaction;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction;

final class CreateOidcTransactionService
{
    use LocatorAwareTrait;

    public function __construct(private readonly TransactionSecretProtector $protector)
    {
    }

    public function create(
        string $issuer,
        string $clientId,
        string $redirectUri,
        string $configurationHash,
        int $ttlSeconds
    ): CreatedOidcTransaction {
        $id = UuidFactory::uuid();
        $state = self::randomBase64Url(32);
        $nonce = self::randomBase64Url(32);
        $pkceVerifier = self::randomBase64Url(64);
        $pkceChallenge = self::base64Url(hash('sha256', $pkceVerifier, true));
        $browserBinding = self::randomBase64Url(32);
        $associatedData = $id . ':' . $configurationHash;

        $table = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoTransactions');
        $entity = $table->newEmptyEntity();
        $entity->set([
            'id' => $id,
            'state_hash' => self::hash($state),
            'nonce_hash' => self::hash($nonce),
            'browser_binding_hash' => self::hash($browserBinding),
            'pkce_verifier_ciphertext' => $this->protector->encrypt($pkceVerifier, $associatedData),
            'configuration_hash' => $configurationHash,
            'issuer' => $issuer,
            'client_id' => $clientId,
            'redirect_uri' => $redirectUri,
            'status' => KeycloakSsoTransaction::STATUS_PENDING,
            'expires' => DateTime::now()->addSeconds($ttlSeconds),
        ]);
        if (!$table->save($entity)) {
            throw new OidcTransactionException('The OIDC transaction could not be created.');
        }

        return new CreatedOidcTransaction(
            $id,
            $state,
            $nonce,
            $pkceVerifier,
            $pkceChallenge,
            $browserBinding
        );
    }

    public static function hash(string $value): string
    {
        return hash('sha256', $value);
    }

    private static function randomBase64Url(int $bytes): string
    {
        return self::base64Url(random_bytes($bytes));
    }

    private static function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
