<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Provisioning;

use Passbolt\KeycloakSso\Error\Exception\ProvisioningException;
use Passbolt\KeycloakSso\Model\Dto\KeycloakAdminEventDto;
use Passbolt\KeycloakSso\Model\Dto\KeycloakAdminEventPageDto;
use Passbolt\KeycloakSso\Model\Dto\KeycloakProvisioningGroupDto;
use Passbolt\KeycloakSso\Model\Dto\KeycloakProvisioningUserDto;
use Passbolt\KeycloakSso\Model\Dto\OidcDiscoveryDocument;
use Passbolt\KeycloakSso\Model\Dto\ProvisioningConfigurationDto;
use Passbolt\KeycloakSso\Utility\Http\OidcHttpClientInterface;

final class KeycloakProvisioningApiService
{
    private const MAX_GROUP_PAGES = 1_000;

    private ?string $accessToken = null;

    /** Construct the narrowly scoped Keycloak Admin API client. */
    public function __construct(
        private readonly ProvisioningConfigurationDto $configuration,
        private readonly OidcDiscoveryDocument $discovery,
        private readonly OidcHttpClientInterface $httpClient,
    ) {
    }

    /**
     * Retrieve one ascending page of relevant saved administrator events.
     *
     * Failed or nested USER events are unrelated to account provisioning and
     * are excluded without reducing the raw page size used for pagination.
     */
    public function events(int $fromMilliseconds, int $first): KeycloakAdminEventPageDto
    {
        if ($fromMilliseconds < 0 || $first < 0) {
            throw new ProvisioningException('The Keycloak administrator event cursor is invalid.');
        }
        $query = implode('&', [
            'operationTypes=CREATE',
            'operationTypes=UPDATE',
            'resourceTypes=USER',
            'dateFrom=' . $fromMilliseconds,
            'direction=asc',
            'first=' . $first,
            'max=' . $this->configuration->batchSize,
        ]);
        $document = $this->httpClient->requestJson(
            'GET',
            $this->configuration->adminApiBaseUrl . '/admin-events?' . $query,
            [],
            $this->authorizationHeader()
        );

        if (!array_is_list($document)) {
            throw new ProvisioningException('Keycloak returned an invalid administrator event collection.');
        }

        $events = [];
        foreach ($document as $event) {
            $parsed = $this->parseEvent($event);
            if ($parsed !== null) {
                $events[] = $parsed;
            }
        }

        return new KeycloakAdminEventPageDto($events, count($document));
    }

    /** Retrieve the current user record instead of trusting saved event representation data. */
    public function user(string $subject): KeycloakProvisioningUserDto
    {
        $this->assertOpaqueIdentifier($subject, 255, 'subject');
        $document = $this->httpClient->requestJson(
            'GET',
            $this->configuration->adminApiBaseUrl . '/users/' . rawurlencode($subject),
            [],
            $this->authorizationHeader()
        );

        foreach (['id', 'email', 'firstName', 'lastName'] as $field) {
            if (!isset($document[$field]) || !is_string($document[$field])) {
                throw new ProvisioningException('Keycloak returned an invalid user record.');
            }
        }
        if (
            !isset($document['emailVerified'], $document['enabled']) ||
            !is_bool($document['emailVerified']) || !is_bool($document['enabled'])
        ) {
            throw new ProvisioningException('Keycloak returned an invalid user status.');
        }
        if (!hash_equals($subject, $document['id'])) {
            throw new ProvisioningException('The Keycloak user identity did not match the requested subject.');
        }

        return new KeycloakProvisioningUserDto(
            $document['id'],
            $document['email'],
            $document['emailVerified'],
            $document['enabled'],
            $document['firstName'],
            $document['lastName']
        );
    }

    /**
     * Retrieve every direct Keycloak group currently assigned to a user.
     *
     * @return list<\Passbolt\KeycloakSso\Model\Dto\KeycloakProvisioningGroupDto>
     */
    public function userGroups(string $subject): array
    {
        $this->assertOpaqueIdentifier($subject, 255, 'subject');
        $groups = [];
        $first = 0;
        for ($page = 0; $page < self::MAX_GROUP_PAGES; $page++) {
            $query = http_build_query([
                'briefRepresentation' => 'true',
                'first' => $first,
                'max' => $this->configuration->batchSize,
            ], '', '&', PHP_QUERY_RFC3986);
            $document = $this->httpClient->requestJson(
                'GET',
                $this->configuration->adminApiBaseUrl . '/users/' . rawurlencode($subject) . '/groups?' . $query,
                [],
                $this->authorizationHeader()
            );
            if (!array_is_list($document)) {
                throw new ProvisioningException('Keycloak returned an invalid user group collection.');
            }
            foreach ($document as $group) {
                $groups[] = $this->parseGroup($group);
            }
            $received = count($document);
            if ($received < $this->configuration->batchSize) {
                return $groups;
            }
            $first += $received;
        }

        throw new ProvisioningException('The Keycloak user group collection exceeded the page limit.');
    }

    /** @return array{Authorization: string} */
    private function authorizationHeader(): array
    {
        if ($this->accessToken === null) {
            $document = $this->httpClient->requestJson('POST', $this->discovery->tokenEndpoint, [
                'grant_type' => 'client_credentials',
                'client_id' => $this->configuration->clientId,
                'client_secret' => $this->configuration->clientSecret,
            ]);
            if (
                !isset($document['access_token'], $document['token_type']) ||
                !is_string($document['access_token']) || !is_string($document['token_type']) ||
                $document['access_token'] === '' || strlen($document['access_token']) > 8_192 ||
                strcasecmp($document['token_type'], 'Bearer') !== 0 ||
                preg_match('/[\x00-\x20\x7F]/', $document['access_token'])
            ) {
                throw new ProvisioningException('Keycloak returned an invalid service-account token response.');
            }
            $this->accessToken = $document['access_token'];
        }

        return ['Authorization' => 'Bearer ' . $this->accessToken];
    }

    /** Parse one exact successful root-user event, or ignore an unrelated USER event. */
    private function parseEvent(mixed $event): ?KeycloakAdminEventDto
    {
        if (!is_array($event)) {
            throw new ProvisioningException('Keycloak returned an invalid administrator event.');
        }
        foreach (['id', 'operationType', 'resourceType', 'resourcePath'] as $field) {
            if (!isset($event[$field]) || !is_string($event[$field])) {
                throw new ProvisioningException('Keycloak returned an invalid administrator event.');
            }
        }
        if (!isset($event['time']) || !is_int($event['time']) || $event['time'] < 0) {
            throw new ProvisioningException('Keycloak returned an invalid administrator event timestamp.');
        }
        $this->assertOpaqueIdentifier($event['id'], 64, 'event identifier');
        if (!in_array($event['operationType'], ['CREATE', 'UPDATE'], true) || $event['resourceType'] !== 'USER') {
            throw new ProvisioningException('Keycloak returned an administrator event outside the requested policy.');
        }
        if (array_key_exists('error', $event) && $event['error'] !== null) {
            if (
                !is_string($event['error']) || $event['error'] === '' || strlen($event['error']) > 255 ||
                preg_match('/[\x00-\x1F\x7F]/', $event['error'])
            ) {
                throw new ProvisioningException('Keycloak returned an invalid administrator event error.');
            }

            return null;
        }
        if (!preg_match('#^users/([^/]{1,255})$#D', $event['resourcePath'], $matches)) {
            if (
                strlen($event['resourcePath']) <= 1_024 &&
                preg_match('#^users(?:/[^/\x00-\x1F\x7F]{1,255})+/?$#D', $event['resourcePath'])
            ) {
                return null;
            }
            throw new ProvisioningException('Keycloak returned an invalid user resource path.');
        }
        $this->assertOpaqueIdentifier($matches[1], 255, 'subject');

        return new KeycloakAdminEventDto(
            $event['id'],
            $event['time'],
            $event['operationType'],
            $matches[1]
        );
    }

    /** Parse one exact Keycloak group representation. */
    private function parseGroup(mixed $group): KeycloakProvisioningGroupDto
    {
        if (!is_array($group)) {
            throw new ProvisioningException('Keycloak returned an invalid user group.');
        }
        foreach (['id', 'name', 'path'] as $field) {
            if (!isset($group[$field]) || !is_string($group[$field])) {
                throw new ProvisioningException('Keycloak returned an invalid user group.');
            }
        }
        $this->assertOpaqueIdentifier($group['id'], 255, 'group identifier');
        if (
            $group['name'] === '' || mb_strlen($group['name'], 'UTF-8') > 255 ||
            trim($group['name']) !== $group['name'] || !mb_check_encoding($group['name'], 'UTF-8') ||
            preg_match('/[\x00-\x1F\x7F]/', $group['name']) ||
            !str_starts_with($group['path'], '/') || strlen($group['path']) < 2 ||
            mb_strlen($group['path'], 'UTF-8') > 255 ||
            !mb_check_encoding($group['path'], 'UTF-8') || preg_match('/[\x00-\x1F\x7F]/', $group['path'])
        ) {
            throw new ProvisioningException('Keycloak returned an invalid user group profile.');
        }

        return new KeycloakProvisioningGroupDto($group['id'], $group['name'], $group['path']);
    }

    /** Validate one bounded opaque Keycloak identifier without normalization. */
    private function assertOpaqueIdentifier(string $value, int $maximumLength, string $name): void
    {
        if (
            $value === '' || strlen($value) > $maximumLength || trim($value) !== $value ||
            !mb_check_encoding($value, 'UTF-8') || preg_match('/[\x00-\x1F\x7F]/', $value)
        ) {
            throw new ProvisioningException('The Keycloak ' . $name . ' is invalid.');
        }
    }
}
