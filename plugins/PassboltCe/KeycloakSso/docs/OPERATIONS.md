# Operations, migration, and recovery

## Database migration

Take and verify a restorable database backup before migration. Also back up the
deployment configuration needed to interpret existing encrypted data, using a
separate protected secret-backup process. Do not put keys in a database backup.

Migrations must run in timestamp order:

1. `20260903120000_CreateKeycloakSsoTransactions`
2. `20260904120000_CreateKeycloakSsoIdentities`
3. `20260905120000_CreateKeycloakSsoCryptoEnrollments`
4. `20260906120000_CreateKeycloakSsoRotationBarriers`

After applying them, verify the four plugin table groups, unique indexes, and
foreign keys described in the migration source. UUID columns use Passbolt's
ASCII UUID conventions. Issuer and subject columns use binary collation because
both values are opaque and case-sensitive. Server-share, nonce, digest, status,
and protocol fields use binary ASCII collation.

The crypto-enrollment migration creates:

- unique `(user_id, client_enrollment_uuid)` and
  `(identity_id, client_enrollment_uuid)` enrollment constraints;
- identity/status and user/status indexes;
- a globally unique nullable client-nonce hash for replay protection;
- request status/expiry and enrollment/status indexes;
- cascading user and identity foreign keys, with restricted key updates;
- a transaction-to-crypto-request foreign key.

The rotation-barrier migration creates exactly one barrier row per user, a
status/modified index, and a cascading user foreign key. Enrollment/release and
rotation transactions serialize on the same user row.

Fresh install and upgrade use the same migrations. Upgrade does not create an
identity or enrollment for any existing user and does not rewrite users,
resources, OpenPGP keys, or secrets.

### Rollback warning

Schema rollback removes plugin state and cannot restore a revoked or overwritten
server share. Take backups before migration, disable the feature before a schema
rollback, and confirm that all users retain normal Passbolt credentials and
recovery material. Restoring an old database and old KEK state can also restore
previously revoked encrypted shares; treat backup access and restoration as a
security-sensitive incident decision. After rollback/reinstall, require fresh
identity verification and browser-profile enrollment rather than claiming that
destroyed KS was recovered.

## KEK trust model

The implemented backend reads the KEK key ring from the process environment.
In the current deployment model, a Kubernetes Secret may populate that
environment, but this plugin does not call cluster APIs and does not provide a
KMS/HSM adapter.

The API process, workload configuration controller, authorized namespace
administrators, secret backup operators, and any principal able to read the
underlying secret or process environment are inside the KEK trust boundary.
Production controls should include least-privilege RBAC, restricted namespace
administration, encrypted etcd storage, envelope encryption where available,
audited secret reads/changes, protected backups, short-lived operator access,
and separation between database-backup and KEK custodians.

A database dump without a KEK cannot decrypt KS. A host/process compromise that
can read the KEK and database can recover server shares, but still lacks the
profile-resident KD and must also defeat the remaining OIDC/profile/GPGAuth
boundaries. For a high-value or high-assurance deployment, prefer an external
KMS/HSM design in a separately reviewed future milestone; it is not implemented
here.

## KEK rotation runbook

1. Create a new independent 32-byte KEK through the approved secret process.
2. Add it under a new immutable key ID while retaining all current keys.
3. Make the new ID active and restart/reload API processes consistently.
4. Run `bin/cake keycloak_sso_server_shares_rewrap` from the application runtime.
   The command reports counts, never key material.
5. Rerun the command. A second successful run should report zero rows; this is
   the idempotency check.
6. Query operational metadata—not ciphertext or keys—and verify zero active,
   nonrevoked enrollment rows reference the retired key ID.
7. Exercise one non-production enrollment/login and confirm audit events.
8. Review database and secret-backup retention. An old backup may still require
   the old KEK, while retaining it increases the compromise window.
9. Remove the retired key only after the row and backup checks pass.

Each row is locked and conditionally updated. A failure leaves unprocessed rows
under their old key and is safe to retry while both keys remain configured. The
service skips rows already using the active ID, so reruns are idempotent. Never
remove an old key to force success.

## Backup and disaster recovery

- Protect database and KEK backups under separate access controls.
- Document which key IDs are needed by each retained backup.
- A database restore must be paired with a reviewed key-ring version; never
  guess or silently substitute a key.
- Restoring pre-revocation state can make an old encrypted server share present
  again. Keep the feature disabled during restore, reconcile revocations, and
  require fresh enrollment where state is uncertain.
- Lost active KEK with no protected backup makes affected SSO enrollments
  unrecoverable. Normal Passbolt credentials and vault data remain usable; users
  must log in normally and freshly enroll.
- Lost browser profile, inaccessible Keycloak, or corrupt local enrollment uses
  the same normal-login/recovery fallback. Keycloak-only recovery is prohibited.

## Passphrase and OpenPGP-key rotation

Passphrase rotation activates the server-authoritative barrier, revokes and
overwrites all existing shares, invalidates racing requests, deletes returned
local enrollment IDs, and only then changes the key. Completion or failure
never restores old shares. A lost completion response leaves SSO blocked until
an authenticated retry resolves the barrier. Fresh enrollment is mandatory.

Actual OpenPGP key replacement revokes enrollments bound to the previous
fingerprint. The normal encrypted private key and recovery workflow remain the
authority. Never edit enrollment metadata to point at a new fingerprint.
