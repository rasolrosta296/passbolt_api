<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Service\Oidc;

use Cake\TestSuite\TestCase;
use Passbolt\KeycloakSso\Model\Dto\CreatedOidcTransaction;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;
use Passbolt\KeycloakSso\Service\Oidc\AuthorizationRequestService;

final class AuthorizationRequestServiceTest extends TestCase
{
    public function testBuildsFixedAuthorizationCodeRequestWithPkce(): void
    {
        $configuration = new OidcConfigurationDto(
            'https://keyclock.gobaz.ir/realms/passbolt',
            'passbolt-client',
            'secret',
            'https://passbolt.gobaz.ir/auth/keycloak/callback',
            random_bytes(32)
        );
        $transaction = new CreatedOidcTransaction(
            '6af4f5dc-0454-40e4-bf95-09e1687c046e',
            'state-value',
            'nonce-value',
            'verifier-value',
            'challenge-value',
            'binding-value'
        );

        $url = AuthorizationRequestService::buildAuthorizationUrl(
            $configuration,
            'https://keyclock.gobaz.ir/realms/passbolt/protocol/openid-connect/auth',
            $transaction
        );
        parse_str((string)parse_url($url, PHP_URL_QUERY), $query);

        $this->assertSame('code', $query['response_type']);
        $this->assertSame('query', $query['response_mode']);
        $this->assertSame('openid email', $query['scope']);
        $this->assertSame('S256', $query['code_challenge_method']);
        $this->assertSame('challenge-value', $query['code_challenge']);
        $this->assertSame('state-value', $query['state']);
        $this->assertSame('nonce-value', $query['nonce']);
        $this->assertSame($configuration->redirectUri, $query['redirect_uri']);
    }
}
