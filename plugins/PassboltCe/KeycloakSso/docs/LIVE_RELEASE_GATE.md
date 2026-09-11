# Live Keycloak SSO release gate

Run this checklist only in an isolated non-production Passbolt, Keycloak, and
desktop Chrome/Chromium environment. Use a dedicated test user and retain only
sanitized pass/fail evidence. Never capture cookies, authorization codes,
tokens, state, nonce, PKCE values, passphrases, private keys, `KD`, `KS`, KEKs,
HPKE private material, or database ciphertext.

No production deployment is authorized by this checklist. Every mandatory item
must pass against the exact API, extension, and styleguide release revisions.

## Environment and configuration

- Record the API, extension, and styleguide commit IDs; PHP, Node/npm,
  Keycloak, and Chrome/Chromium versions; and the exact public origins without
  secret values.
- Confirm desktop Chrome/Chromium MV3 is the tested browser. Do not claim
  Firefox or Safari support.
- Confirm `App.fullBaseUrl` is the canonical lowercase HTTPS Passbolt origin,
  has no path or explicit default port, and full-base-URL enforcement is active.
- Confirm the configured redirect URI is exactly the same origin plus
  `/auth/keycloak/callback`.
- Confirm the issuer is the exact Keycloak realm issuer, HTTPS, and has no
  trailing slash, query, fragment, credentials, or wildcard.
- Confirm discovery returns the exact issuer and that authorization, token, and
  JWKS endpoints are HTTPS, same-origin, nonredirecting, and accepted by the
  API's egress checks. Do not relax SSRF or TLS validation to pass this check.
- Confirm the confidential client permits only the exact callback, uses
  Authorization Code Flow and PKCE S256, signs ID tokens with RS256, and has
  implicit flow, direct grants, service accounts, and wildcard redirects off.
- Confirm the release ACR returned by Keycloak exactly equals the configured
  policy. Confirm required AMR values only when AMR enforcement is enabled.
- Confirm transaction and KEK keys are independent 32-byte values, are absent
  from source, images, logs, database backups, and reports, and are readable
  only by the intended API runtime and authorized secret custodians.
- Confirm all four Keycloak migration groups are applied and their unique
  indexes, binary issuer/subject collation, and foreign keys match the migration
  source.

## Authentication and linking boundaries

- Prove normal Passbolt passphrase/GPGAuth login and recovery work before SSO
  enrollment.
- While logged out of Passbolt, prove identity linking, unlinking, enrollment,
  rotation, and enrollment completion are rejected.
- Complete a base OIDC identity proof and prove
  `/auth/is-authenticated.json` remains unauthenticated.
- Link only after a normal Passbolt session plus fresh Keycloak proof and
  explicit confirmation. Prove a different authenticated Passbolt user,
  unverified email, email mismatch, duplicate Passbolt email, changed subject,
  or changed issuer fails closed.
- Replay the confirmation POST/result and prove it cannot create or move a
  second identity link.
- Confirm result and failure pages contain only generic text and do not extend
  proof lifetime.

## Browser-profile enrollment

- Begin from the durable extension-owned Quick Access Chrome tab while normally
  logged in. Confirm opening Keycloak cannot destroy the worker that owns the
  enrollment and does not resize the normal browser window.
- Confirm Keycloak interaction completes before the extension-owned passphrase
  field appears and enrollment never auto-starts on mount.
- Enter the existing Passbolt passphrase only in Quick Access. Confirm it never
  appears in page DOM, content-script messages, URLs, browser local/session
  storage, IndexedDB, logs, analytics, or API requests.
- Prove a wrong passphrase, cancelled flow, identity mismatch, invalid OpenPGP
  transcript, or API failure creates no usable local enrollment.
- After success, inspect storage: IndexedDB contains the profile-resident
  non-extractable `KD` and signing private `CryptoKey`, `C2`, IVs, canonical
  context, and public metadata. `exportKey` on both private keys must fail.
- Inspect API persistence: it contains encrypted `KS`, KEK key ID/nonce,
  signing public key, client blob digest, canonical context, and ownership
  metadata; it must not contain plaintext `KS`, `KD`, `P`, `C1`, `C2`, a private
  signing key, a Passbolt private key, or OIDC credentials.
- Simulate local IndexedDB persistence failure after server commit. Confirm no
  SSO login is possible from that profile and record/remove the orphaned server
  enrollment through the authenticated revocation path.

## Cryptographic login and final authority

- Completely terminate the existing Passbolt session and clear the standard
  short-lived passphrase cache before each boundary test.
- Start login by explicit click in the durable extension-owned Quick Access tab.
  Confirm no transient client nonce, HPKE private key, release capability, or
  passphrase is placed in a URL or persistent storage.
- Confirm every unlock sends `prompt=login`, `max_age=0`, and an essential exact
  ACR request; an old Keycloak browser session must still require interactive
  authentication.
- Confirm a successful OIDC callback produces only a one-time release
  capability and leaves `/auth/is-authenticated.json` unauthenticated.
- Abort after successful `KS` release and local passphrase recovery but before
  GPGAuth. Confirm Passbolt remains unauthenticated and no passphrase cache was
  written.
- Force final GPGAuth failure after successful OIDC/release/recovery. Confirm
  Passbolt remains unauthenticated, post-login is not called, and no passphrase
  cache was written.
- Complete the normal flow. Confirm the unchanged GPGAuth challenge succeeds
  before authenticated state appears. Only then may the normal
  `rememberMe=false` 60-second `browser.storage.session` passphrase cache be
  populated; confirm logout clears it.
- Confirm the cache is absent from `browser.storage.local`, IndexedDB, cookies,
  page/content-script state, and server persistence. Treat the alarm interval as
  scheduler-driven, not a hard erasure deadline.

## Replay, substitution, and race gates

- Send two concurrent identical release requests with the original result
  cookie and signed body. Exactly one may succeed; both-success is a release
  blocker. Both-failure requires investigation and a fresh transaction.
- Prove replay of state, callback, identity result, crypto result, release
  capability, request ID, and client nonce fails closed.
- Prove wrong profile signing key, enrollment ID, user, identity, client blob
  digest, client nonce, HPKE recipient, canonical context, fingerprint,
  protocol version, or crypto suite fails closed.
- Prove modified `C2`, inner/outer IV, HPKE ciphertext/encapsulation, server-share
  ciphertext/nonce/AAD, or release transcript fails closed.
- Prove noncanonical, malformed, alternate, reordered, extended, or trailing
  CBOR input is rejected.
- Prove wrong/missing ACR, stale/future/missing `auth_time`, required AMR
  mismatch, issuer/audience/authorized-party/nonce mismatch, invalid signature,
  `alg=none`, algorithm confusion, token-controlled key URL, and unknown/rotated
  signing keys fail closed. Valid Keycloak JWKS rotation must recover only
  through trusted discovery/JWKS retrieval.
- After fresh OIDC but before release, disable the Passbolt test user from a
  separate administrator session. Resume the flow and prove no `KS` release or
  Passbolt authentication occurs. Restore the user only after recording the
  result.
- Repeat with revoked identity and revoked enrollment. Confirm neither can
  release `KS`.

## Rotation, unlink, and key operations

- With an active enrollment, begin normal passphrase rotation and prove the
  server-authoritative barrier atomically revokes shares and invalidates racing
  enrollment/release work.
- Prove a concurrent new enrollment cannot commit across the barrier and a
  concurrent release ordered after it cannot release `KS`.
- Complete rotation, prove the old and copied local enrollment remain unusable,
  prove normal login with the new passphrase works, then require fresh
  browser-profile enrollment.
- Force revocation/API failure and prove private-key update fails closed rather
  than bypassing the barrier. A failed barrier must never restore an old share.
- Unlink through authenticated, CSRF-protected, explicitly confirmed Quick
  Access. Confirm server shares/identity are revoked first, local enrollment is
  removed, stale copies cannot obtain `KS`, and normal Passbolt login remains.
- Rewrap a test enrollment from KEK A to KEK B while both keys are available.
  Verify login and stored key ID B, rerun for idempotency, and remove A only
  after zero active rows and backup-retention review.
- Rotate the Keycloak client secret and transaction key in a controlled test;
  in-flight OIDC work must fail while new transactions work afterward.

## Browser-profile and incident assumptions

- Copy an enrolled browser profile under the supported environment. Confirm
  profile copy alone cannot release `KS`.
- Confirm and record the accepted Standard-mode result: copied enrolled profile
  plus qualifying fresh Keycloak authentication plus an honest available API
  can complete SSO unlock. Do not describe the keys as device-bound,
  hardware-backed, or uncloneable.
- Confirm Keycloak logout does not retroactively terminate an already-created
  Passbolt session, and Passbolt logout does not terminate Keycloak. Record this
  as residual session risk and set session policies independently.
- Confirm disabling a Keycloak account blocks the next fresh OIDC unlock but
  does not retroactively erase an existing Passbolt session. Confirm disabling a
  Passbolt user blocks release/final authentication at the next server check.
- Review logs and audit output for every success/failure above. Events may use
  allowlisted categories and internal user UUIDs where documented; no sensitive
  runtime or identity claim data may appear.

## Release decision

Production is **NO-GO** until all mandatory live checks pass, the exact release
artifacts are rebuilt and reloaded in Chrome/Chromium, known dependency
advisories are either remediated or explicitly accepted by the security owner,
and the database/KEK backup and incident-response procedures have been tested.
Any unexpected success in a negative test is a protocol release blocker; do not
weaken the protocol or test to proceed.
