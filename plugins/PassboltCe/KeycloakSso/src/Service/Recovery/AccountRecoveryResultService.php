<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Recovery;

use App\Model\Entity\AuthenticationToken;
use Cake\Datasource\ConnectionManager;
use Cake\I18n\DateTime;
use Cake\ORM\Locator\LocatorAwareTrait;
use Passbolt\KeycloakSso\Error\Exception\OidcTransactionException;
use Passbolt\KeycloakSso\Model\Dto\AccountRecoveryGrant;
use Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction;
use Passbolt\KeycloakSso\Service\Transaction\CreateOidcTransactionService;
use SensitiveParameter;

final class AccountRecoveryResultService
{
    use LocatorAwareTrait;

    /** Construct a consumer bound to the current exact OIDC configuration. */
    public function __construct(
        private readonly string $expectedIssuer,
        private readonly string $configurationHash,
        private readonly AccountRecoveryIdentityProofProtector $identityProofs,
    ) {
    }

    /**
     * Atomically consume a Keycloak proof and mint a normal Passbolt recovery token.
     */
    public function consume(
        #[SensitiveParameter]
        string $resultToken
    ): AccountRecoveryGrant {
        if (!preg_match('/^[A-Za-z0-9_-]{43}$/', $resultToken)) {
            throw new OidcTransactionException('The account recovery result is invalid or has already been used.');
        }
        /** @var \Cake\Database\Connection $connection */
        $connection = ConnectionManager::get('default');

        return $connection->transactional(function () use ($resultToken): AccountRecoveryGrant {
            $transactions = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoTransactions');
            /** @var \Passbolt\KeycloakSso\Model\Entity\KeycloakSsoTransaction|null $transaction */
            $transaction = $transactions->find()->where([
                'result_token_hash' => CreateOidcTransactionService::hash($resultToken),
                'purpose' => KeycloakSsoTransaction::PURPOSE_ACCOUNT_RECOVERY,
                'status' => KeycloakSsoTransaction::STATUS_SUCCEEDED,
                'issuer' => $this->expectedIssuer,
                'configuration_hash' => $this->configurationHash,
                'result_expires >' => DateTime::now(),
                'requested_user_id IS NOT' => null,
                'link_identity_ciphertext IS NOT' => null,
            ])->epilog('FOR UPDATE')->first();
            if ($transaction === null) {
                throw new OidcTransactionException(
                    'The account recovery result is invalid or has already been used.'
                );
            }
            $userId = (string)$transaction->requested_user_id;
            $identityBinding = $this->identityProofs->reveal(
                $transaction,
                (string)$transaction->link_identity_ciphertext
            );
            if (!hash_equals($userId, $identityBinding->userId)) {
                throw new OidcTransactionException('The account recovery identity is unavailable.');
            }
            $identity = $this->fetchTable('Passbolt/KeycloakSso.KeycloakSsoIdentities')->find()->where([
                'id' => $identityBinding->identityId,
                'user_id' => $identityBinding->userId,
                'issuer' => $identityBinding->issuer,
                'subject' => $identityBinding->subject,
            ])->epilog('FOR UPDATE')->first();
            if ($identity === null) {
                throw new OidcTransactionException('The account recovery identity is unavailable.');
            }
            $user = $this->fetchTable('Users')->find('activeNotDeletedNotDisabledContainRole')->where([
                'Users.id' => $userId,
            ])->epilog('FOR UPDATE')->first();
            if ($user === null) {
                throw new OidcTransactionException('The account recovery user is unavailable.');
            }
            /** @var \App\Model\Table\AuthenticationTokensTable $authenticationTokens */
            $authenticationTokens = $this->fetchTable('AuthenticationTokens');
            $token = $authenticationTokens->generate(
                $userId,
                AuthenticationToken::TYPE_RECOVER
            );
            $affected = $transactions->updateAll(
                [
                    'status' => KeycloakSsoTransaction::STATUS_RESULT_CONSUMED,
                    'result_token_hash' => null,
                    'result_expires' => null,
                    'link_identity_ciphertext' => null,
                    'modified' => DateTime::now(),
                ],
                [
                    'id' => $transaction->id,
                    'status' => KeycloakSsoTransaction::STATUS_SUCCEEDED,
                ]
            );
            if ($affected !== 1) {
                throw new OidcTransactionException(
                    'The account recovery result is invalid or has already been used.'
                );
            }

            return new AccountRecoveryGrant($userId, (string)$token->token);
        });
    }
}
