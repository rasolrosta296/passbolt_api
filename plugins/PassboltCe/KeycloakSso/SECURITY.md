# Keycloak SSO security contract

The plugin implements OIDC identity proof, permanent identity linking, and the
reviewed version-one cryptographic release protocol. OIDC and server-share
release do not authenticate a user to Passbolt. Only unchanged GPGAuth may do
so after the extension locally reconstructs and validates the passphrase.

## Trust boundary

After a successful OIDC callback the plugin may report that Keycloak
authentication succeeded and that one existing, active Passbolt user has the
same verified email address. Milestone two may persist an identity link only
after the additional controls below. The plugin must not:

- persist a CakePHP/Passbolt authentication identity or write `Auth.user`;
- create a Passbolt session, access token, JWT, or refresh token;
- call or modify GPGAuth or JWT authentication services;
- store a Passbolt private key, plaintext passphrase, client key, or plaintext
  server share;
- create a user or move a link between users based on email;
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

## Identity-linking boundary

An identity link maps the case-sensitive, opaque tuple `(issuer, subject)` to
exactly one Passbolt user UUID. Email is used only during fresh enrollment to
prove that the OIDC identity resolves to the same active Passbolt user; it is
never an identity key and never moves an existing link.

Creating or deleting a link requires all of the following:

- a server-side Passbolt session whose `Auth.user.id` matches the request
  authentication identity; bearer/JWT or OIDC-only identity is insufficient;
- a protected plugin endpoint and CSRF validation;
- explicit user confirmation;
- for linking, a new purpose-bound OIDC transaction whose state, nonce, PKCE
  verifier, browser binding, and short lifetime retain all milestone-one
  protections;
- an exact match between the authenticated user UUID and the sole active,
  nondeleted, nondisabled Passbolt user discovered from the verified OIDC email;
- atomic one-time consumption and database-enforced collision constraints.

The identity table enforces unique `(issuer, subject)` and `(issuer, user_id)`
tuples. Its user foreign key uses `ON DELETE CASCADE`: hard-deleting a Passbolt
user removes the now-ownerless identifier and its audit metadata rather than
blocking user erasure or leaving personal data orphaned. Soft-deleted and
disabled users are rejected at both enrollment start and confirmation.

Changing a Keycloak email, Passbolt email, subject, realm, or issuer never
automatically relinks or migrates an identity. A changed issuer is a distinct
provider namespace. Unlinking affects only the authenticated user's link for
the configured issuer and never disables normal GPGAuth.

## Cryptographic release boundary

Each browser-profile enrollment requires an existing GPGAuth session, CSRF,
the existing issuer/subject link, fresh interactive OIDC, the current
passphrase in extension-owned UI, and a transcript signature from the existing
OpenPGP private key. The API stores the independently generated server share
only under XChaCha20-Poly1305 with a deployment KEK that must remain outside the
database boundary. Login requires proof of the profile-resident non-extractable
signing key, fresh `prompt=login`/`max_age=0` OIDC with exact ACR and fresh
`auth_time`, then a second signed one-time release request. The share is sent
only through RFC 9180 HPKE to the request-bound ephemeral recipient.

The extension stores a profile-resident non-extractable `KD`, a
profile-resident non-extractable P-256 signing key, `C2`, IVs, canonical context,
and public metadata in IndexedDB. These keys provide no platform-keystore
binding and no resistance to copying an enrolled browser profile. The accepted first-release model allows SSO
unlock from a copied enrolled Chrome/Chromium profile when the attacker can
also complete qualifying Keycloak authentication against an honest API.

Passphrases collected for enrollment are requested only after the fresh OIDC
stage completes, use a dedicated extension-owned Quick Access form, and do not
traverse page/content-script messaging, `passbolt.passphrase.request`, or
remember-passphrase storage. The form clears its controlled value before the
asynchronous enrollment operation proceeds.
Passphrases recovered during login exist only in extension background memory,
are passed directly to unchanged GPGAuth, and are never persisted.

Passphrase rotation is fail closed: after the existing client validates and
prepares the key update, the plugin locks the current user's database row and
atomically activates a unique per-user rotation barrier, revokes all crypto
enrollments, overwrites their encrypted shares, and invalidates in-flight
enrollment/release state. Enrollment/release starts, enrollment commits, and
final releases take the same user lock and reject an active barrier, so a
racing operation cannot survive.
The barrier is completed or failed only with a random capability scoped to the
normally authenticated user; a failed rotation never restores old shares. The
extension deletes returned local enrollment records before changing the key.
An uncertain completion leaves the barrier active and SSO blocked, while
normal GPGAuth remains usable and a fresh browser-profile enrollment is always
required after rotation.

Security invariant: no enrollment may commit and no server share may be
released while the owning user's rotation barrier is active. Starting before
the barrier is insufficient; the final database transaction must serialize on
the user row and recheck the barrier.

The fixed protocol, amended transcript schemas, rotation rules, and accepted
trust model are frozen in `docs/CRYPTOGRAPHIC_SSO_PROTOCOL_V1.md`. Active KEK
rotation is completed by configuring both old and new keys, selecting the new
active key, running `keycloak_sso_server_shares_rewrap`, then removing the old
key only after verification and backup-retention review.

## Deferred work

Firefox/Safari support, general UI polish, WebAuthn/platform binding,
device-to-device enrollment, and account-recovery changes remain outside the
first release. OIDC-derived Passbolt session creation remains prohibited.
