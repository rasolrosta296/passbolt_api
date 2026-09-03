<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Utility\Http;

use Cake\Http\Client;
use JsonException;
use Passbolt\KeycloakSso\Error\Exception\OidcNetworkException;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;
use Throwable;

final class SafeOidcHttpClient implements OidcHttpClientInterface
{
    private readonly string $allowedOrigin;

    public function __construct(
        private readonly OidcConfigurationDto $configuration,
        private readonly ?Client $client = null,
        private readonly ?HostResolverInterface $resolver = null,
    ) {
        $this->allowedOrigin = self::origin($configuration->issuer);
    }

    public function requestJson(string $method, string $url, array $form = []): array
    {
        $this->assertSafeUrl($url);
        $client = $this->client ?? new Client([
            'timeout' => OidcConfigurationDto::HTTP_TIMEOUT_SECONDS,
            'redirect' => 0,
        ]);

        try {
            $options = [
                'redirect' => 0,
                'timeout' => OidcConfigurationDto::HTTP_TIMEOUT_SECONDS,
                'headers' => ['Accept' => 'application/json'],
            ];
            if ($form !== []) {
                $options['type'] = 'form';
            }
            $response = $client->send(strtoupper($method), $url, $form, $options);
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

    public function assertSafeUrl(string $url): void
    {
        $parts = parse_url($url);
        if (
            $parts === false || ($parts['scheme'] ?? null) !== 'https' || empty($parts['host']) ||
            isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment']) ||
            !hash_equals($this->allowedOrigin, self::origin($url))
        ) {
            throw new OidcNetworkException('The OIDC endpoint URL is not allowed.');
        }

        $host = (string)$parts['host'];
        if (!mb_check_encoding($host, 'ASCII')) {
            throw new OidcNetworkException('The OIDC endpoint host is invalid.');
        }
        $addresses = ($this->resolver ?? new SystemHostResolver())->resolve($host);
        if ($addresses === []) {
            throw new OidcNetworkException('The OIDC endpoint host could not be resolved.');
        }
        foreach ($addresses as $address) {
            if (filter_var(
                $address,
                FILTER_VALIDATE_IP,
                FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
            ) === false) {
                throw new OidcNetworkException('The OIDC endpoint resolves to a prohibited network.');
            }
        }
    }

    private static function origin(string $url): string
    {
        $parts = parse_url($url);
        if ($parts === false || !isset($parts['scheme'], $parts['host'])) {
            return '';
        }
        $port = $parts['port'] ?? (($parts['scheme'] === 'https') ? 443 : 80);

        return strtolower($parts['scheme']) . '://' . strtolower($parts['host']) . ':' . $port;
    }
}
