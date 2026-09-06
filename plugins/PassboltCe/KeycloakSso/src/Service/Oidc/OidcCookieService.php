<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Service\Oidc;

use Cake\Http\Cookie\Cookie;
use Cake\I18n\DateTime;
use Passbolt\KeycloakSso\Model\Dto\OidcConfigurationDto;

final class OidcCookieService
{
    public const BROWSER_BINDING_COOKIE = '__Host-passbolt_keycloak_binding';
    public const RESULT_COOKIE = '__Host-passbolt_keycloak_result';
    public const LINK_RESULT_COOKIE = '__Host-passbolt_keycloak_link_result';
    public const CRYPTO_RESULT_COOKIE = '__Host-passbolt_keycloak_crypto_result';

    /**
     * Create the short-lived browser-binding cookie.
     */
    public static function browserBinding(string $value): Cookie
    {
        return self::create($value, OidcConfigurationDto::TRANSACTION_TTL_SECONDS, self::BROWSER_BINDING_COOKIE);
    }

    /**
     * Create the short-lived one-time result cookie.
     */
    public static function result(string $value): Cookie
    {
        return self::create($value, OidcConfigurationDto::RESULT_TTL_SECONDS, self::RESULT_COOKIE);
    }

    /**
     * Create a purpose-specific one-time identity-link result cookie.
     */
    public static function linkResult(string $value): Cookie
    {
        return self::create(
            $value,
            OidcConfigurationDto::IDENTITY_LINK_RESULT_TTL_SECONDS,
            self::LINK_RESULT_COOKIE
        );
    }

    /**
     * Create the short-lived HttpOnly cryptographic result cookie.
     */
    public static function cryptoResult(string $value): Cookie
    {
        return self::create($value, OidcConfigurationDto::CRYPTO_RESULT_TTL_SECONDS, self::CRYPTO_RESULT_COOKIE);
    }

    /**
     * Create an expired secure cookie for explicit cleanup.
     */
    public static function expired(string $name): Cookie
    {
        return (new Cookie($name))
            ->withValue('expired')
            ->withPath('/')
            ->withSecure(true)
            ->withHttpOnly(true)
            ->withSameSite(Cookie::SAMESITE_LAX)
            ->withExpired();
    }

    /**
     * Create a Secure, HttpOnly, SameSite=Lax host-only cookie.
     */
    private static function create(string $value, int $ttlSeconds, string $name): Cookie
    {
        return (new Cookie($name))
            ->withValue($value)
            ->withPath('/')
            ->withSecure(true)
            ->withHttpOnly(true)
            ->withSameSite(Cookie::SAMESITE_LAX)
            ->withExpiry(DateTime::now()->addSeconds($ttlSeconds));
    }
}
