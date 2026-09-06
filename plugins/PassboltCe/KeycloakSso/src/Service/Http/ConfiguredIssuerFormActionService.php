<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Http;

use App\Middleware\ContentSecurityPolicyExtension;
use App\Middleware\ContentSecurityPolicyMiddleware;
use Cake\Http\Exception\InternalErrorException;
use Passbolt\KeycloakSso\Configuration\OidcConfigurationService;
use Psr\Http\Message\ServerRequestInterface;

final class ConfiguredIssuerFormActionService
{
    /**
     * Permit only the strictly configured issuer origin for this request.
     */
    public function allow(ServerRequestInterface $request): void
    {
        $configurationService = new OidcConfigurationService();
        $configuration = $configurationService->load();
        $extension = $request->getAttribute(ContentSecurityPolicyMiddleware::EXTENSION_ATTRIBUTE);
        if (!$extension instanceof ContentSecurityPolicyExtension) {
            throw new InternalErrorException('The request-scoped CSP extension is unavailable.');
        }

        $extension->addFormActionOrigin($configurationService->issuerOrigin($configuration->issuer));
    }
}
