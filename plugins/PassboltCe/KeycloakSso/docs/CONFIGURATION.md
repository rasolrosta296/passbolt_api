# Configuration contract

Set configuration through the deployment environment or secret-management
integration. Never commit secret values. Examples below are placeholders, not
working secrets.

`App.fullBaseUrl` must be one canonical HTTPS origin with a lowercase DNS host,
no path, query, fragment, credentials, or explicit default port. The redirect
URI must use that same origin when Passbolt full-base-URL enforcement is active.

| Variable | Secret | Required format and behavior |
| --- | --- | --- |
| `KEYCLOAK_SSO_ENABLED` | No | Explicit boolean. Missing means disabled. An ambiguous value fails application bootstrap. When false, the plugin and all its routes are absent. |
| `KEYCLOAK_SSO_ISSUER` | No | Exact HTTPS Keycloak realm issuer, such as `https://id.example.test/realms/example`; no trailing slash, query, fragment, credentials, or non-realm path. Discovery must return this exact issuer. The issuer host must resolve only to public, non-reserved addresses. |
| `KEYCLOAK_SSO_CLIENT_ID` | No | Non-empty, whitespace/control-free client ID, at most 255 bytes. |
| `KEYCLOAK_SSO_CLIENT_SECRET` | Yes | Non-empty Keycloak confidential-client secret with no surrounding whitespace or control characters. Store only in the deployment secret store. |
| `KEYCLOAK_SSO_REDIRECT_URI` | No | Exact HTTPS URL ending in `/auth/keycloak/callback`; no query, fragment, credentials, or wildcard. |
| `KEYCLOAK_SSO_TRANSACTION_ENCRYPTION_KEY` | Yes | Canonical base64 encoding of exactly 32 random bytes. Protects short-lived transaction material and keyed configuration hashes. |
| `KEYCLOAK_SSO_RELEASE_ACR` | No | Required exact ACR text, non-empty and at most 255 bytes. Keycloak must return it for every cryptographic release. |
| `KEYCLOAK_SSO_RELEASE_AMR` | No | Optional. Empty/unset disables AMR enforcement. Otherwise a JSON array of 1–16 unique strings, each 1–64 bytes with no surrounding whitespace. Every value is required exactly. |
| `KEYCLOAK_SSO_SERVER_SHARE_ACTIVE_KEY_ID` | No | Active KEK identifier, 1–64 lowercase ASCII letters, digits, dot, underscore, or hyphen. It must exist in the key ring. |
| `KEYCLOAK_SSO_SERVER_SHARE_KEYRING` | Yes | JSON object of 1–16 key-ID to canonical-base64 values. Each value decodes to exactly 32 random bytes. Only the active ID encrypts; retained older IDs decrypt during rotation. |

Use placeholders such as `<OIDC_CLIENT_SECRET>`, `<BASE64_32_BYTE_KEY>`, and
`{"kek-2026-01":"<BASE64_32_BYTE_KEY>"}` in templates. Generate real values
with an approved secret-generation process and never print them in CI output.

## Validation and failure behavior

The enable flag is evaluated during application bootstrap. With the feature
enabled, the remaining OIDC and cryptographic values are strictly loaded before
the relevant operation or maintenance command and fail closed if missing or
invalid. No default issuer, endpoint, redirect, ACR, client secret, or key is
accepted. Discovery, token, and JWKS endpoints must be same-origin with the
configured issuer, HTTPS, non-redirecting, size-bounded, and safe under DNS/IP
validation.

Changing the OIDC client secret or transaction-encryption key changes the keyed
transaction configuration hash and invalidates in-flight OIDC transactions.
Changing issuer, client ID, or redirect URI also invalidates in-flight work and
must be treated as a controlled outage. Issuer changes create a different
identity namespace and require explicit relinking and fresh enrollment.

Changing ACR or AMR policy can cause in-flight releases to fail their current
proof and should be done during a controlled window. It never weakens an
already-required proof.

Adding a KEK or changing the active key does not alter client envelopes. Do not
remove an old KEK until every active row has been successfully rewrapped and
backup-retention consequences have been reviewed. Removing a still-needed KEK
makes affected server shares permanently unreleasable and forces re-enrollment.

## Feature disablement

Set `KEYCLOAK_SSO_ENABLED=false` and restart the application. The plugin is not
loaded, its routes are unavailable, site settings do not advertise the feature,
and the extension/styleguide expose no usable Keycloak action. Existing
identity/enrollment rows and local browser-profile artifacts remain encrypted
and untouched. They cannot release KS while disabled. Re-enabling with the same
valid configuration can make still-active enrollments usable again; operators
who require permanent disablement must perform authenticated unlink/revocation
before disabling.
