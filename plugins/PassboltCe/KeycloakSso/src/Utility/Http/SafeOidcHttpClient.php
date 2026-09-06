<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Utility\Http;

use Cake\Http\Client;
use CurlHandle;
use JsonException;
use Passbolt\KeycloakSso\Error\Exception\OidcNetworkException;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;
use SensitiveParameter;
use Throwable;

final class SafeOidcHttpClient implements OidcHttpClientInterface
{
    private readonly string $allowedOrigin;

    /**
     * Construct a client pinned to the configured issuer origin.
     */
    public function __construct(
        OidcConfigurationDto $configuration,
        private readonly ?Client $client = null,
        private readonly ?HostResolverInterface $resolver = null,
    ) {
        $this->allowedOrigin = self::origin($configuration->issuer);
    }

    /**
     * Retrieve a size-bounded JSON response without redirects.
     *
     * @return array<string, mixed>
     */
    public function requestJson(string $method, string $url, #[SensitiveParameter]
    array $form = []): array
    {
        $addresses = $this->assertSafeUrl($url);
        $parts = parse_url($url);
        assert(is_array($parts) && isset($parts['host']));
        $port = $parts['port'] ?? 443;
        $pinnedAddresses = array_map(
            static fn (string $address): string => str_contains($address, ':') ? '[' . $address . ']' : $address,
            $addresses
        );
        $client = $this->client ?? new Client([
            'timeout' => OidcConfigurationDto::HTTP_TIMEOUT_SECONDS,
            'redirect' => 0,
        ]);

        try {
            $options = [
                'redirect' => 0,
                'timeout' => OidcConfigurationDto::HTTP_TIMEOUT_SECONDS,
                'headers' => ['Accept' => 'application/json'],
                'curl' => [
                    CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
                    CURLOPT_RESOLVE => [
                        $parts['host'] . ':' . $port . ':' . implode(',', $pinnedAddresses),
                    ],
                    CURLOPT_MAXFILESIZE => OidcConfigurationDto::MAX_HTTP_RESPONSE_BYTES,
                    CURLOPT_NOPROGRESS => false,
                    CURLOPT_XFERINFOFUNCTION => static function (
                        CurlHandle $_handle,
                        float $downloadTotal,
                        float $downloaded,
                        float $_uploadTotal,
                        float $_uploaded
                    ): int {
                        $maximum = OidcConfigurationDto::MAX_HTTP_RESPONSE_BYTES;

                        return $downloadTotal > $maximum || $downloaded > $maximum ? 1 : 0;
                    },
                ],
            ];
            $response = match (strtoupper($method)) {
                'GET' => $client->get($url, [], $options),
                'POST' => $client->post($url, $form, $options),
                default => throw new OidcNetworkException('The OIDC HTTP method is not allowed.'),
            };
        } catch (Throwable $exception) {
            throw new OidcNetworkException('The OIDC provider request failed.', 0, $exception);
        }

        $status = $response->getStatusCode();
        if ($status >= 300 && $status < 400) {
            throw new OidcNetworkException('OIDC endpoint redirects are not allowed.');
        }
        if ($status < 200 || $status >= 300) {
            throw new OidcNetworkException('The OIDC provider returned an unsuccessful status.');
        }

        $declaredLength = $response->getHeaderLine('Content-Length');
        if ($declaredLength !== '' && (int)$declaredLength > OidcConfigurationDto::MAX_HTTP_RESPONSE_BYTES) {
            throw new OidcNetworkException('The OIDC provider response is too large.');
        }
        $body = $response->getStringBody();
        if (strlen($body) > OidcConfigurationDto::MAX_HTTP_RESPONSE_BYTES) {
            throw new OidcNetworkException('The OIDC provider response is too large.');
        }

        try {
            $decoded = json_decode($body, true, 32, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new OidcNetworkException('The OIDC provider returned invalid JSON.', 0, $exception);
        }
        if (!is_array($decoded)) {
            throw new OidcNetworkException('The OIDC provider returned an invalid document.');
        }

        return $decoded;
    }

    /**
     * Reject unsafe schemes, origins, credentials, and resolved destinations.
     *
     * @return list<string> Validated addresses to pin for the outbound connection.
     */
    public function assertSafeUrl(string $url): array
    {
        $parts = parse_url($url);
        if (
            $parts === false || ($parts['scheme'] ?? null) !== 'https' || empty($parts['host']) ||
            isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment']) ||
            !hash_equals($this->allowedOrigin, self::origin($url))
        ) {
            throw new OidcNetworkException('The OIDC endpoint URL is not allowed.');
        }

        $host = $parts['host'];
        if (!mb_check_encoding($host, 'ASCII')) {
            throw new OidcNetworkException('The OIDC endpoint host is invalid.');
        }
        $addresses = ($this->resolver ?? new SystemHostResolver())->resolve($host);
        if ($addresses === []) {
            throw new OidcNetworkException('The OIDC endpoint host could not be resolved.');
        }
        foreach ($addresses as $address) {
            if (
                filter_var(
                    $address,
                    FILTER_VALIDATE_IP,
                    FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
                ) === false
            ) {
                throw new OidcNetworkException('The OIDC endpoint resolves to a prohibited network.');
            }
        }

        return array_values(array_unique($addresses));
    }

    /**
     * Normalize a URL to a scheme, host, and explicit port origin.
     */
    private static function origin(string $url): string
    {
        $parts = parse_url($url);
        if ($parts === false || !isset($parts['scheme'], $parts['host'])) {
            return '';
        }
        $port = $parts['port'] ?? ($parts['scheme'] === 'https' ? 443 : 80);

        return strtolower($parts['scheme']) . '://' . strtolower($parts['host']) . ':' . $port;
    }
}
