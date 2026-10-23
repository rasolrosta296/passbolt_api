<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Configuration;

use JsonException;
use Passbolt\KeycloakSso\Error\Exception\OidcConfigurationException;
use Passbolt\KeycloakSso\Model\Dto\AccountRecoveryConfigurationDto;

final class AccountRecoveryConfigurationService
{
    /** @param array<string, string|false>|null $environment */
    public function load(?array $environment = null): AccountRecoveryConfigurationDto
    {
        $read = static fn (string $name): string|false => $environment === null
            ? getenv($name)
            : ($environment[$name] ?? false);
        $enabled = filter_var(
            $read(KeycloakSsoEnvironment::ACCOUNT_RECOVERY_ENABLED),
            FILTER_VALIDATE_BOOLEAN,
            FILTER_NULL_ON_FAILURE
        );
        if ($enabled !== true) {
            throw new OidcConfigurationException('Keycloak-assisted account recovery is not explicitly enabled.');
        }
        $acr = $this->required(
            $read(KeycloakSsoEnvironment::ACCOUNT_RECOVERY_ACR),
            KeycloakSsoEnvironment::ACCOUNT_RECOVERY_ACR,
            255
        );

        return new AccountRecoveryConfigurationDto(
            $acr,
            $this->amr($read(KeycloakSsoEnvironment::ACCOUNT_RECOVERY_AMR))
        );
    }

    /** @return list<string> */
    private function amr(string|false $value): array
    {
        if ($value === false || $value === '') {
            return [];
        }
        try {
            $items = json_decode($value, true, 4, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new OidcConfigurationException(
                KeycloakSsoEnvironment::ACCOUNT_RECOVERY_AMR . ' must be an empty value or a JSON string array.'
            );
        }
        if (!is_array($items) || !array_is_list($items) || count($items) > 16) {
            throw new OidcConfigurationException(
                KeycloakSsoEnvironment::ACCOUNT_RECOVERY_AMR . ' must be a JSON string array.'
            );
        }
        $result = [];
        foreach ($items as $item) {
            if (
                !is_string($item) || $item === '' || strlen($item) > 64 || trim($item) !== $item ||
                preg_match('/[\x00-\x1F\x7F]/', $item)
            ) {
                throw new OidcConfigurationException(
                    KeycloakSsoEnvironment::ACCOUNT_RECOVERY_AMR . ' contains an invalid value.'
                );
            }
            $result[] = $item;
        }
        if (count(array_unique($result)) !== count($result)) {
            throw new OidcConfigurationException(
                KeycloakSsoEnvironment::ACCOUNT_RECOVERY_AMR . ' contains duplicate values.'
            );
        }

        return $result;
    }

    /** Validate one required bounded text value. */
    private function required(string|false $value, string $name, int $maxLength): string
    {
        if (
            !is_string($value) || $value === '' || strlen($value) > $maxLength || trim($value) !== $value ||
            preg_match('/[\x00-\x1F\x7F]/', $value)
        ) {
            throw new OidcConfigurationException($name . ' is missing or invalid.');
        }

        return $value;
    }
}
