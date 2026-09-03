# Keycloak SSO milestone-one security contract

This plugin implements only an OpenID Connect identity proof and existing-user
discovery. It does not authenticate a user to Passbolt and does not unlock a
Passbolt vault.

## Trust boundary

After a successful OIDC callback the plugin may report that Keycloak
authentication succeeded and that one existing, active Passbolt user has the
same verified email address. It must not:

- persist a CakePHP/Passbolt authentication identity or write `Auth.user`;
- create a Passbolt session, access token, JWT, or refresh token;
- call or modify GPGAuth or JWT authentication services;
- store a Passbolt private key, passphrase, or wrapping secret;
- create or permanently link a user;
- use or enable the Passbolt Pro SSO plugin.

`/auth/is-authenticated` must remain unauthenticated after this plugin completes.

## OIDC requirements

- Authorization Code Flow with PKCE S256 and a GET/query callback.
- Exact, HTTPS issuer and fixed client/redirect configuration.
- Server-side, short-lived transactions with hashed state, nonce, and browser
  binding, plus an authenticated-encrypted PKCE verifier.
- Atomic `pending` to `processing` claim and terminal consumption on success or
  failure.
- Discovery/JWKS requests reject redirects, untrusted origins, unsafe IP
  destinations, invalid TLS, and oversized responses.
- ID tokens require an allowed asymmetric algorithm, trusted JWKS signature,
  exact issuer, audience, applicable `azp`, `exp`, bounded `iat`, optional `nbf`,
  exact nonce, `sub`, valid email, and literal boolean `email_verified=true`.
- Token-provided `jku` and `x5u` are ignored.
- The callback redirects with HTTP 303 to a fixed, one-time result endpoint.

## Sensitive-data handling

Authorization codes, access/refresh/ID tokens, claims, client secrets, PKCE
verifiers, raw state/nonces/browser bindings, encryption keys, private keys, and
passphrases must never be logged or included in responses.

## Deferred work

Identity linking by `(issuer, sub)`, Passbolt session creation, browser-extension
changes, private-key unlock, and every cryptographic continuation are explicitly
outside milestone one and require a separate security review.
