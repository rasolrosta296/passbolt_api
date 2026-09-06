<?php
declare(strict_types=1);

/**
 * Passbolt ~ Open source password manager for teams
 * Copyright (c) Passbolt SA (https://www.passbolt.com)
 *
 * Licensed under GNU Affero General Public License version 3 of the or any later version.
 * For full copyright and license information, please see the LICENSE.txt
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright     Copyright (c) Passbolt SA (https://www.passbolt.com)
 * @license       https://opensource.org/licenses/AGPL-3.0 AGPL License
 * @link          https://www.passbolt.com Passbolt(tm)
 */
namespace App\Middleware;

use InvalidArgumentException;

/**
 * Collect trusted, request-scoped additions to the generated CSP policy.
 */
final class ContentSecurityPolicyExtension
{
    /**
     * @var array<string, true>
     */
    private array $formActionOrigins = [];

    /**
     * Add one exact HTTPS origin to form-action.
     */
    public function addFormActionOrigin(string $origin): void
    {
        $origin = $this->normalizeHttpsOrigin($origin);
        $this->formActionOrigins[$origin] = true;
    }

    /**
     * Return the validated form-action origins in insertion order.
     *
     * @return list<string>
     */
    public function formActionOrigins(): array
    {
        return array_keys($this->formActionOrigins);
    }

    /**
     * Accept only a complete HTTPS origin, never a URL or wildcard source.
     */
    private function normalizeHttpsOrigin(string $origin): string
    {
        $parts = parse_url($origin);
        if ($parts === false) {
            throw new InvalidArgumentException('A CSP form-action extension must be an exact HTTPS origin.');
        }
        $host = $parts['host'] ?? '';
        if (
            ($parts['scheme'] ?? null) !== 'https' ||
            !$this->isValidHost($host) || isset($parts['user']) || isset($parts['pass']) ||
            isset($parts['query']) || isset($parts['fragment']) ||
            (isset($parts['path']) && $parts['path'] !== '')
        ) {
            throw new InvalidArgumentException('A CSP form-action extension must be an exact HTTPS origin.');
        }

        $normalized = 'https://' . strtolower($host);
        $port = $parts['port'] ?? null;
        if (is_int($port) && $port !== 443) {
            $normalized .= ':' . $port;
        }

        return $normalized;
    }

    /**
     * Reject wildcard and malformed hosts while permitting valid DNS and IP literals.
     */
    private function isValidHost(string $host): bool
    {
        if ($host === '' || str_contains($host, '*')) {
            return false;
        }

        $ipHost = $host;
        if (str_starts_with($host, '[') && str_ends_with($host, ']')) {
            $ipHost = substr($host, 1, -1);
        }

        return filter_var($ipHost, FILTER_VALIDATE_IP) !== false ||
            filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false;
    }
}
