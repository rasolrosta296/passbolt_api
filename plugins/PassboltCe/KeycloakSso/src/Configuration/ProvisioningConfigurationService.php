<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Configuration;

use Cake\Validation\Validation;
use Passbolt\KeycloakSso\Error\Exception\OidcConfigurationException;
use Passbolt\KeycloakSso\Model\Dto\ProvisioningConfigurationDto;
use SensitiveParameter;

final class ProvisioningConfigurationService
{
    /**
     * Load the independently credentialed, read-only provisioning client configuration.
     *
     * @param array<string, string|false>|null $environment Test override; production reads process environment.
     */
    public function load(#[SensitiveParameter]
    ?array $environment = null): ProvisioningConfigurationDto
    {
        $read = static function (string $name) use ($environment): string|false {
            return $environment === null ? getenv($name) : ($environment[$name] ?? false);
        };

        $enabled = filter_var(
            $read(KeycloakSsoEnvironment::PROVISIONING_ENABLED),
            FILTER_VALIDATE_BOOLEAN,
            FILTER_NULL_ON_FAILURE
        );
        if ($enabled !== true) {
            throw new OidcConfigurationException('Keycloak user provisioning is not explicitly enabled.');
        }

        $oidc = (new OidcConfigurationService())->load($environment);
        $clientId = $this->required(
            $read(KeycloakSsoEnvironment::PROVISIONING_CLIENT_ID),
            KeycloakSsoEnvironment::PROVISIONING_CLIENT_ID
        );
        $clientSecret = $this->required(
            $read(KeycloakSsoEnvironment::PROVISIONING_CLIENT_SECRET),
            KeycloakSsoEnvironment::PROVISIONING_CLIENT_SECRET
        );
        $actorUserId = $this->required(
            $read(KeycloakSsoEnvironment::PROVISIONING_ACTOR_USER_ID),
            KeycloakSsoEnvironment::PROVISIONING_ACTOR_USER_ID
        );
        if (!Validation::uuid($actorUserId)) {
            throw new OidcConfigurationException(
                KeycloakSsoEnvironment::PROVISIONING_ACTOR_USER_ID . ' must be a UUID.'
            );
        }
        if (strlen($clientId) > 255) {
            throw new OidcConfigurationException(
                KeycloakSsoEnvironment::PROVISIONING_CLIENT_ID . ' is too long.'
            );
        }

        $initialLookback = $this->boundedInteger(
            $read(KeycloakSsoEnvironment::PROVISIONING_INITIAL_LOOKBACK_SECONDS),
            KeycloakSsoEnvironment::PROVISIONING_INITIAL_LOOKBACK_SECONDS,
            ProvisioningConfigurationDto::DEFAULT_INITIAL_LOOKBACK_SECONDS,
            ProvisioningConfigurationDto::MIN_INITIAL_LOOKBACK_SECONDS,
            ProvisioningConfigurationDto::MAX_INITIAL_LOOKBACK_SECONDS
        );
        $overlap = $this->boundedInteger(
            $read(KeycloakSsoEnvironment::PROVISIONING_OVERLAP_SECONDS),
            KeycloakSsoEnvironment::PROVISIONING_OVERLAP_SECONDS,
            ProvisioningConfigurationDto::DEFAULT_OVERLAP_SECONDS,
            ProvisioningConfigurationDto::MIN_OVERLAP_SECONDS,
            ProvisioningConfigurationDto::MAX_OVERLAP_SECONDS
        );
        $batchSize = $this->boundedInteger(
            $read(KeycloakSsoEnvironment::PROVISIONING_BATCH_SIZE),
            KeycloakSsoEnvironment::PROVISIONING_BATCH_SIZE,
            ProvisioningConfigurationDto::DEFAULT_BATCH_SIZE,
            ProvisioningConfigurationDto::MIN_BATCH_SIZE,
            ProvisioningConfigurationDto::MAX_BATCH_SIZE
        );

        /** @var array{path: string} $issuerParts */
        $issuerParts = parse_url($oidc->issuer);
        $realm = substr($issuerParts['path'], strlen('/realms/'));
        $origin = (new OidcConfigurationService())->issuerOrigin($oidc->issuer);

        return new ProvisioningConfigurationDto(
            $oidc->issuer,
            $origin . '/admin/realms/' . rawurlencode($realm),
            $clientId,
            $clientSecret,
            strtolower($actorUserId),
            $initialLookback,
            $overlap,
            $batchSize
        );
    }

    /** Read one required, whitespace-free provisioning setting. */
    private function required(string|false $value, string $name): string
    {
        if (
            !is_string($value) || $value === '' || trim($value) !== $value ||
            preg_match('/[\x00-\x1F\x7F]/', $value)
        ) {
            throw new OidcConfigurationException($name . ' is required and must not contain whitespace or controls.');
        }

        return $value;
    }

    /** Read one optional integer and enforce its security bound. */
    private function boundedInteger(
        string|false $value,
        string $name,
        int $default,
        int $minimum,
        int $maximum
    ): int {
        if ($value === false || $value === '') {
            return $default;
        }
        if (!ctype_digit($value)) {
            throw new OidcConfigurationException($name . ' must be an integer.');
        }
        $integer = (int)$value;
        if ($integer < $minimum || $integer > $maximum) {
            throw new OidcConfigurationException(sprintf(
                '%s must be between %d and %d.',
                $name,
                $minimum,
                $maximum
            ));
        }

        return $integer;
    }
}
