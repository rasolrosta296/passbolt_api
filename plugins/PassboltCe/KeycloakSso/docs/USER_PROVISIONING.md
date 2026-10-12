# Keycloak administrator-created user provisioning

## Security contract

The provisioning subsystem observes persisted Keycloak administrator events for
users created through **Users → Add user** or the equivalent authenticated
Keycloak Admin REST API operation. It creates an ordinary inactive Passbolt
user and the normal one-time Passbolt setup invitation. It does not:

- create or alter a Keycloak identity link;
- authenticate the user to Passbolt;
- create a Passbolt session, JWT, refresh token, OpenPGP key, or SSO enrollment;
- map Keycloak roles to Passbolt administrator privileges;
- move or merge existing Passbolt users.

The user must complete the normal Passbolt client-side OpenPGP setup. The user
must subsequently complete the existing GPGAuth + fresh OIDC identity-link and
cryptographic enrollment protocols before Keycloak cryptographic SSO is usable.

## Source and trust boundaries

The first version supports Keycloak 26.3.3 administrator events only. A
dedicated confidential Keycloak service-account client is granted the minimum
realm-management roles required to read saved administrator events and user
profiles. The provisioning client is separate from the browser-facing OIDC
client.

This intentionally delegates ordinary Passbolt invitation authority to every
Keycloak administrator or automation that is already authorized to create or
update users in the configured realm. The event source is not restricted to one
Admin Console operator. Restrict Keycloak `manage-users` and equivalent
fine-grained administration permissions accordingly.

The command accepts only `CREATE` and `UPDATE` events whose resource type is
`USER`. `UPDATE` is necessary when an administrator creates a user before
marking the email verified. The current Keycloak user record must satisfy all
of the following at processing time:

- enabled is exactly `true`;
- emailVerified is exactly `true`;
- email, firstName, and lastName are present and valid;
- the issuer is the exact configured issuer.

An existing nondeleted Passbolt username, subject collision, or
provisioning-record collision fails closed and requires administrator review.
A soft-deleted Passbolt username does not block a genuinely new Keycloak
identity with a new immutable subject from receiving a new Passbolt invitation.
The old account and its cryptographic ownership are not restored, merged, or
transferred. Email is discovery/provisioning metadata and is never the
permanent SSO identity key.

## Idempotency and reliability

Keycloak 26.3.3 administrator event IDs are persisted with an exact issuer
namespace. A database unique constraint on `(issuer, event_id)` prevents event
replay. A second unique constraint on `(issuer, subject)` prevents one Keycloak
identity from provisioning multiple Passbolt accounts. A unique `user_id`
constraint prevents a Passbolt user from being claimed by multiple provisioning
records.

Polling uses an overlap window. Duplicate events are harmless, failed events
remain eligible for retry, and concurrent command executions rely on database
claims and uniqueness constraints rather than timing.

## Required Keycloak configuration

In the target realm:

1. Enable saving administrator events.
2. Keep event representation storage disabled.
3. Retain administrator events for at least seven days.
4. Create a dedicated confidential client with service accounts enabled.
5. Grant only the realm-management permissions needed to view events and users.

## Environment

```text
KEYCLOAK_SSO_PROVISIONING_ENABLED=true
KEYCLOAK_SSO_PROVISIONING_CLIENT_ID=<dedicated read-only client>
KEYCLOAK_SSO_PROVISIONING_CLIENT_SECRET=<secret-store value>
KEYCLOAK_SSO_PROVISIONING_ACTOR_USER_ID=<active Passbolt administrator UUID>
KEYCLOAK_SSO_PROVISIONING_INITIAL_LOOKBACK_SECONDS=86400
KEYCLOAK_SSO_PROVISIONING_OVERLAP_SECONDS=300
KEYCLOAK_SSO_PROVISIONING_BATCH_SIZE=100
KEYCLOAK_SSO_GROUP_PROVISIONING_ENABLED=false
KEYCLOAK_SSO_GROUP_RECONCILIATION_ENABLED=false
KEYCLOAK_SSO_DEPROVISIONING_ENABLED=false
KEYCLOAK_SSO_DEPROVISIONING_GRACE_SECONDS=604800
KEYCLOAK_SSO_REACTIVATION_ENABLED=false
```

The actor UUID identifies the active Passbolt administrator recorded as the
inviter. The provisioning client secret must come from a secret store and must
never be logged or committed.

Group provisioning is independently disabled by default. Enabling it delegates
creation of mapped Passbolt groups to Keycloak group assignments. The actor is
installed as the initial Passbolt group manager; provisioned users are always
ordinary members and never receive manager or Passbolt administrator rights.

## Keycloak 26.3.3 setup

In **Realm settings → Events → Admin events settings**:

1. Enable **Save events**.
2. Keep **Include representation** disabled.
3. Configure an expiration of at least seven days.

Create a separate confidential client for provisioning, enable its service
account, and assign only the `realm-management` client roles `view-events` and
`view-users`. If the realm's composite-role layout requires `query-users` for a
direct user lookup, add only that role after confirming the Admin API returns
403 without it. Do not grant `manage-users`, `realm-admin`, or any role capable
of changing users.

## Execution

Preview one synchronization pass without writing checkpoints, users, or
invitations:

```text
bin/cake keycloak_sso_provision_users --dry-run
```

Run one synchronization pass:

```text
bin/cake keycloak_sso_provision_users
```

Run the non-dry command once per minute using the deployment's existing job
scheduler. Concurrent executions are safe: the event claim and user creation
are serialized at the database level, and uniqueness constraints remain the
final authority.

For authoritative lifecycle operation, schedule separate bounded jobs in this
order and alert on every nonzero exit:

1. `keycloak_sso_provision_users`
2. `keycloak_sso_reconcile_users`
3. `keycloak_sso_sync_groups`

The reconciliation interval is the maximum expected propagation delay for a
Keycloak disable, delete, or group-membership removal. Do not run permanent
deletion from an unattended wildcard or bulk loop.

## Group synchronization and end-to-end encryption

When `KEYCLOAK_SSO_GROUP_PROVISIONING_ENABLED=true`, preview group changes with:

```text
bin/cake keycloak_sso_sync_groups --dry-run
```

Apply one bounded synchronization pass with:

```text
bin/cake keycloak_sso_sync_groups
```

The permanent mapping key is `(issuer, Keycloak group ID)`. A Keycloak group
path is used only as the initial Passbolt display name and is never used to
adopt an existing Passbolt group. Name collisions fail closed.

The API automatically completes membership only when the Passbolt user is
active and the mapped group grants no resource for which that user lacks an
encrypted secret. Otherwise the desired membership remains `pending_activation`
or `pending_crypto`. The server never fabricates or decrypts resource secrets.
Pending cryptographic memberships require an authenticated and unlocked group
manager client to use the normal Passbolt sharing operation and encrypt each
required secret to the new user's OpenPGP public key.

When `KEYCLOAK_SSO_GROUP_RECONCILIATION_ENABLED=true`, a complete successful
Keycloak group response is authoritative for plugin-managed memberships. A
missing assignment is removed through Passbolt's normal group-user deletion
service, which preserves secrets when the user retains access by another path
and applies the deployment's configured resource-expiry policy to access that
is actually lost.
Provider errors, incomplete pagination, malformed responses, and outages never
produce removals. Manually managed memberships that have no plugin provenance
are never removed. Empty mapped groups and group names are retained; automatic
group deletion or rename could affect resource ownership and is deliberately
outside this lifecycle.

The command reports counts only. It never prints Keycloak event IDs, subjects,
emails, access tokens, or client credentials.

## Deprovisioning and deletion

Deprovisioning is independently disabled by default. Once
`KEYCLOAK_SSO_DEPROVISIONING_ENABLED=true`, run:

```text
bin/cake keycloak_sso_reconcile_users --dry-run
bin/cake keycloak_sso_reconcile_users
```

The command performs an exact current-user Admin API lookup for every
provisioned subject. `enabled=false` or an authenticated exact 404 immediately:

- disables the Passbolt user;
- applies the deployment's configured resource-expiry policy to the disabled
  user's affected resources;
- invalidates pending cryptographic transactions and overwrites/revokes KS;
- removes the Keycloak identity link;
- removes plugin-managed group memberships.

Only an exact 404 is interpreted as absence. TLS, DNS, timeout, 401, 403, 429,
5xx, malformed JSON, and all other failures leave account/access state
unchanged and make the command fail. Before checking individual users, the
command requires a successful Admin user-collection preflight so a proxy or
path returning 404 for the complete Admin API cannot masquerade as mass user
deletion. A disabled user is not eligible for automatic deletion. An absent
user enters quarantine for the configured grace period (seven days by default).
Reappearance after an exact Keycloak 404 never automatically re-enables the
Passbolt account.

Automatic reactivation is separately disabled by default. When
`KEYCLOAK_SSO_REACTIVATION_ENABLED=true`, the reconciler can clear `disabled`
only for the same immutable provisioned `(issuer, subject)` whose suspension
was originally written and timestamp-marked by this plugin because Keycloak
returned `enabled=false`. An existing or subsequently changed Passbolt-side
suspension, a legacy unmarked suspension, a deleted/recreated Keycloak user,
an inactive provisioning actor, or a deleted Passbolt user always fails closed
and remains subject to administrator review.

Reactivation restores only the active state of the same Passbolt account. It
does not recreate the identity link, SSO enrollment/server share, sessions,
JWTs, removed group memberships, or access whose encrypted secrets were
expired during deprovisioning. The user must use normal Passbolt access, link
the Keycloak identity again, and create a fresh browser-profile enrollment.
Subsequent group synchronization may restore only memberships that still meet
the normal Passbolt cryptographic sharing requirements.

After the grace period, permanent Passbolt soft deletion requires a fresh
Keycloak 404 and explicit one-user approval:

```text
bin/cake keycloak_sso_delete_user --user-id <PASSBOLT_USER_UUID> --confirm DELETE
```

Native Passbolt delete rules remain authoritative. If the user is an owner or
sole group manager requiring transfer, deletion fails closed. Perform the
normal Passbolt administrative ownership/manager transfer and retry. Never
schedule this command with an unreviewed list of user identifiers.

## Operational limitations

- A Keycloak email or name change does not update an existing Passbolt user.
- Re-enabling the same disabled Keycloak subject can re-enable only a matching
  plugin-marked Passbolt suspension when the independent reactivation flag is
  enabled. Recreated/previously absent subjects and Passbolt-admin suspensions
  are never automatically re-enabled.
- A collision with any nondeleted Passbolt username is terminal and requires
  administrator review. A soft-deleted username may be reused only by a new
  Keycloak subject. The old `(issuer, subject)` remains reserved and can never
  silently provision or link a replacement account.
- A forgotten Passbolt passphrase is not recoverable from Keycloak identity
  proof alone. Use an enrolled browser profile or normal usable recovery
  material. If neither remains, replacing the account is destructive: delete
  it only after normal ownership/access review, recreate the Keycloak user so
  it receives a new subject, and let the fresh `CREATE` event issue a new
  Passbolt invitation. The replacement has a new Passbolt UUID and OpenPGP key;
  old encrypted access is not inherited.
- Provisioning does not link the Keycloak identity. The user must finish the
  normal Passbolt invitation and then use the existing explicit linking flow.
- Fully automatic server-side membership is intentionally impossible once a
  group contains resources that are not already encrypted for the new user.
- Keycloak group rename/deletion does not automatically rename/delete the
  Passbolt group. Membership access is still reconciled by immutable group ID.
