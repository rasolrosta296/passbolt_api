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
- Expired or abandoned transaction material is opportunistically erased when a
  new transaction starts and can also be erased by scheduling the plugin's
  `keycloak_sso_transactions_cleanup` command.
- Discovery/JWKS requests reject redirects, untrusted origins, unsafe IP
  destinations, invalid TLS, and oversized responses. Validated DNS results are
  pinned into the cURL connection to prevent DNS rebinding between validation
  and connection.
- ID tokens require an allowed asymmetric algorithm, trusted JWKS signature,
  exact issuer, audience, applicable `azp`, `exp`, bounded `iat`, optional `nbf`,
  exact nonce, `sub`, valid email, and literal boolean `email_verified=true`.
- Token-provided `jku`, `x5u`, `jwk`, `x5c`, and unsupported critical headers
  are rejected. Signing keys come only from the discovered trusted JWKS URI.
- The callback redirects with HTTP 303 to a fixed, one-time result endpoint.

## Sensitive-data handling

Authorization codes, access/refresh/ID tokens, claims, client secrets, PKCE
verifiers, raw state/nonces/browser bindings, encryption keys, private keys, and
passphrases must never be logged or included in responses.

Because Authorization Code Flow uses the required GET/query callback, the
Kubernetes ingress, reverse proxy, service mesh, APM, WAF, and load balancer
must be configured not to log query strings for `/auth/keycloak/callback`.
Application-level audit events intentionally contain only fixed messages and
allowlisted failure categories.

## Deferred work

Identity linking by `(issuer, sub)`, Passbolt session creation, browser-extension
changes, private-key unlock, and every cryptographic continuation are explicitly
outside milestone one and require a separate security review.
