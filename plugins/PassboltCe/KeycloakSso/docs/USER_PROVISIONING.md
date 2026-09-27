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
- update, move, merge, disable, or delete existing Passbolt users.

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

An existing Passbolt username, deleted-user username reuse, subject collision,
or provisioning-record collision fails closed and requires administrator
review. Email is discovery/provisioning metadata and is never the permanent SSO
identity key.

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
```

The actor UUID identifies the active Passbolt administrator recorded as the
inviter. The provisioning client secret must come from a secret store and must
never be logged or committed.

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

The command reports counts only. It never prints Keycloak event IDs, subjects,
emails, access tokens, or client credentials.

## Operational limitations

- This release creates users only; it never changes or deprovisions them.
- A Keycloak email or name change does not update an existing Passbolt user.
- A Keycloak disable/delete does not disable/delete the Passbolt user.
- A collision with any existing Passbolt username, including a soft-deleted
  user, is terminal and requires administrator review.
- Provisioning does not link the Keycloak identity. The user must finish the
  normal Passbolt invitation and then use the existing explicit linking flow.
