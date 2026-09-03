<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Utility\Http;

final class SystemHostResolver implements HostResolverInterface
{
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
        $records = dns_get_record($host, DNS_A | DNS_AAAA);
        if (is_array($records)) {
            foreach ($records as $record) {
                $address = $record['ip'] ?? $record['ipv6'] ?? null;
                if (is_string($address)) {
                    $addresses[] = $address;
                }
            }
        }

        return array_values(array_unique($addresses));
    }
}
