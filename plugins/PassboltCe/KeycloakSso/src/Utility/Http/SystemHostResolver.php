<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Utility\Http;

use Closure;

final class SystemHostResolver implements HostResolverInterface
{
    /**
     * @var \Closure(string, int): (array<int, array<string, mixed>>|false)
     */
    private readonly Closure $dnsRecordResolver;

    /**
     * @var \Closure(string): (array<int, string>|false)
     */
    private readonly Closure $ipv4FallbackResolver;

    /**
     * @param (\Closure(string, int): (array<int, array<string, mixed>>|false))|null $dnsRecordResolver
     * @param (\Closure(string): (array<int, string>|false))|null $ipv4FallbackResolver
     */
    public function __construct(?Closure $dnsRecordResolver = null, ?Closure $ipv4FallbackResolver = null)
    {
        $this->dnsRecordResolver = $dnsRecordResolver ??
            static fn (string $host, int $type): array|false => dns_get_record($host, $type);
        $this->ipv4FallbackResolver = $ipv4FallbackResolver ??
            static fn (string $host): array|false => gethostbynamel($host);
    }

    /**
     * Resolve all A and AAAA addresses for a host.
     *
     * @return list<string>
     */
    public function resolve(string $host): array
    {
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return [$host];
        }

        $addresses = [];
        foreach ([DNS_A, DNS_AAAA] as $type) {
            $records = ($this->dnsRecordResolver)($host, $type);
            if (is_array($records)) {
                foreach ($records as $record) {
                    $address = $record['ip'] ?? $record['ipv6'] ?? null;
                    if (is_string($address)) {
                        $addresses[] = $address;
                    }
                }
            }
        }

        // Some container DNS/NSS configurations resolve through the system resolver
        // while PHP's direct DNS API returns no records. Use the system IPv4
        // resolver only as a fallback; SafeOidcHttpClient validates and pins
        // every returned address before an outbound request is made.
        if ($addresses === []) {
            $fallbackAddresses = ($this->ipv4FallbackResolver)($host);
            if (is_array($fallbackAddresses)) {
                foreach ($fallbackAddresses as $address) {
                    if (is_string($address)) {
                        $addresses[] = $address;
                    }
                }
            }
        }

        return array_values(array_unique($addresses));
    }
}
