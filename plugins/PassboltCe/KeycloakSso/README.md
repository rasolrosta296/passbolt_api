# Keycloak cryptographic SSO for Passbolt CE

This plugin provides the reviewed Keycloak identity-linking and browser-profile
cryptographic SSO protocol. It does not replace Passbolt authentication. OIDC
and server-share release only let the Chrome/Chromium extension recover the
existing private-key passphrase locally; unchanged GPGAuth remains the sole
authority that creates a Passbolt authenticated state.

The frozen wire protocol is specified in
[`docs/CRYPTOGRAPHIC_SSO_PROTOCOL_V1.md`](docs/CRYPTOGRAPHIC_SSO_PROTOCOL_V1.md).
Operators must also read [`docs/OPERATIONS.md`](docs/OPERATIONS.md),
[`docs/INCIDENT_RESPONSE.md`](docs/INCIDENT_RESPONSE.md), and
[`docs/DEPENDENCY_RISK.md`](docs/DEPENDENCY_RISK.md), then complete
[`docs/LIVE_RELEASE_GATE.md`](docs/LIVE_RELEASE_GATE.md) before enabling the
feature.

## Supported scope

- Passbolt CE API based on the release documented in the release candidate.
- Desktop Chrome/Chromium MV3 extension only.
- Existing Passbolt users who explicitly link an identity and enroll a browser
  profile while normally authenticated through GPGAuth.
- One Keycloak identity per issuer and Passbolt user.

Firefox, Safari, WebAuthn/platform binding, device-to-device enrollment, and
automatic account creation or recovery are not supported.

## Installation order

1. Back up the Passbolt database and secret configuration. Confirm that the
   normal recovery kit and normal GPGAuth login work before changing anything.
2. Install the API release candidate with PHP 8.2+, `ext-gmp`, `ext-sodium`,
   the locked Composer dependencies, and the plugin migrations.
3. Apply the migrations in timestamp order. Do not enable the feature until
   migration verification is complete.
4. Configure the canonical HTTPS Passbolt origin and all variables in
   [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md). Keep secret values outside
   source control and application logs.
5. Configure the Keycloak confidential client as described below.
6. Build the browser extension against the matching styleguide release
   candidate using Node 22.23.1 and npm 10.9.8, then build the production MV3
   target with `npm run build:chromium-mv3`.
7. Enable the feature for a non-production cohort, verify normal login first,
   then exercise link, enrollment, SSO login, unlink, and passphrase rotation.

No user is linked or enrolled automatically. Existing Passbolt OpenPGP data is
not migrated or rewritten.

## Keycloak client contract

Create a dedicated confidential OIDC client in the configured realm:

- Standard flow / Authorization Code Flow: enabled.
- Implicit flow, direct-access grants, service accounts, and device flow:
  disabled unless independently required for another client. They are not used
  by this integration.
- Valid redirect URI: exactly the configured Passbolt
  `/auth/keycloak/callback` HTTPS URL; do not use wildcards.
- Web origins: the exact Passbolt origin only, if the Keycloak version requires
  it. No wildcard origin.
- Client authentication: enabled, with the secret supplied only through the
  deployment secret store.
- PKCE method: S256.
- ID-token signing algorithm: RS256.
- Required scopes: `openid email`.
- The `email`, literal boolean `email_verified`, `sub`, `auth_time`, and `acr`
  claims must be present when required by the flow.
- Configure an authentication flow that returns the exact release ACR. The
  server requests it as essential and requires `prompt=login`, `max_age=0`, and
  a fresh `auth_time` inside the five-minute release transaction.
- If AMR enforcement is configured, Keycloak must return every exact configured
  value. AMR enforcement is otherwise off.

Keycloak MFA does not satisfy Passbolt MFA. Passbolt applies its normal MFA and
post-login policy only after successful GPGAuth.

## User lifecycle

```text
no identity link -> identity linked -> browser-profile enrolled -> SSO usable
```

- Linking and enrollment require a normal Passbolt session plus a fresh
  Keycloak proof for the same user.
- Passphrase change revokes all enrollments before the credential update and
  requires fresh enrollment.
- OpenPGP-key replacement revokes enrollments bound to the previous fingerprint
  and requires fresh enrollment.
- Unlink revokes and erases server shares, deletes the identity, and asks the
  extension to delete local enrollment data. Normal Passbolt credentials remain.
- Feature disablement makes all plugin routes unavailable. Existing database
  rows and local encrypted enrollment artifacts are retained but no server share
  can be released.
- Loss of a profile or Keycloak access falls back to normal Passbolt login and
  recovery. Keycloak alone never provisions a new browser profile.

## Accepted Standard-mode limitation

An enrolled browser-profile copy, qualifying fresh Keycloak authentication,
and an available honest Passbolt API are sufficient to perform SSO unlock.
Profile copy alone is insufficient because the API still gates the encrypted
server share on fresh OIDC and an active enrollment.

The profile-resident non-extractable KD and profile-resident non-extractable
signing key are browser-profile protections only:

- non-extractable is not hardware-bound;
- non-extractable is not device-bound;
- non-extractable is not uncloneable.

Normal Passbolt passphrase and recovery login remain the break-glass path.
