# Incident-response runbook

Keep the feature disabled while identity, key, or data integrity is uncertain.
Preserve audit records without copying callback query strings, tokens,
capabilities, ciphertexts, or key material into tickets or chat systems.

| Incident | Immediate containment | Rotate/revoke and re-enroll | Existing resources and recovery |
| --- | --- | --- | --- |
| Keycloak client secret compromised | Rotate the client secret, terminate suspect Keycloak sessions, and inspect client/audit events. | Rotation invalidates in-flight OIDC transactions. Re-enrollment is not normally required unless identity/session integrity is doubtful. | Existing Passbolt resources are unchanged; normal login/recovery works. |
| Transaction-encryption key compromised | Disable the feature, replace the key, expire/clean all in-flight OIDC and crypto requests, and inspect callback/access logs. | All in-flight capabilities become invalid. Revoke/re-enroll profiles if the attacker may also have obtained transaction records or usable OIDC proof. | Persistent encrypted server shares and vault data are not directly encrypted by this key. Normal recovery works. |
| Active server-share KEK compromised | Disable releases, preserve evidence, add a new KEK, rewrap uncompromised active rows, and revoke affected enrollments when confidentiality cannot be established. | A mere rotation cannot undo disclosure of KS. Profiles whose KS may have been exposed require revocation and fresh enrollment. | KS alone cannot decrypt C1 without profile KD. Existing vault resources and normal login remain available. |
| Enrolled browser profile stolen/copied | Revoke the user's enrollment and identity link as appropriate; terminate Keycloak sessions and secure the Keycloak account. | Fresh browser-profile enrollment is required. Treat a copied profile plus qualifying Keycloak access and an honest API as sufficient for SSO unlock. | Profile copy alone does not release KS. Normal Passbolt credentials remain valid unless separately compromised. |
| Passbolt API host compromised | Disable the feature and isolate/rebuild the host; rotate client secret, transaction key, and all KEKs reachable by the process; review database and TLS integrity. | Revoke and freshly enroll where KS or request integrity may have been exposed. Consider normal Passbolt key/passphrase rotation under the broader Passbolt incident plan. | A malicious API still lacks profile KD, but can attack delivery/authentication and collect encrypted artifacts. Follow the main Passbolt compromise procedure. |
| Keycloak account or realm signing key compromised | Disable affected identity releases, terminate sessions, reset authenticators, rotate signing keys/client credentials as applicable, and inspect issuer events. | Revoke affected links/enrollments when unauthorized fresh OIDC proofs may have occurred. Relink/re-enroll after trust is restored. | Keycloak alone has no Passbolt key material. Normal Passbolt login/recovery works. |
| User requests unlink | Require a normal authenticated Passbolt session, CSRF, and explicit confirmation. | Server transaction revokes/overwrites enrollments, deletes identity state, and returns IDs for local cleanup. Reuse requires explicit relink and fresh enrollment. | The encrypted OpenPGP key and normal passphrase are untouched. |
| Passbolt passphrase changed | Let the approved rotation barrier run before the private-key update. Investigate any barrier or cleanup failure rather than bypassing it. | Old shares are never restored; fresh enrollment is mandatory. | Normal login uses the new passphrase. Resources are not re-encrypted by this SSO envelope action. |
| OpenPGP private key changed | Revoke every enrollment bound to the old fingerprint and verify the key-change audit trail. | Fresh enrollment against the new fingerprint is mandatory. | Follow normal Passbolt key rotation/recovery procedures for resource access. |
| Issuer or realm changed | Treat the new exact issuer as a different provider namespace; disable the old flow during migration. | Explicitly unlink, configure the new issuer, relink, and freshly enroll. Never rewrite issuer/subject rows in place. | Email is not authority. Existing resources and normal Passbolt recovery are unaffected. |

For every event, also disable affected Passbolt users when required by the main
incident policy, retain evidence, and verify that logs did not capture OIDC
query strings or secrets. Restoring a database backup can restore revoked rows;
keep releases disabled until revocation state is reconciled.
