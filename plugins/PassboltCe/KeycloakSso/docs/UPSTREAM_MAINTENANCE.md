# Upstream maintenance and integration impact

Keep API, browser extension, and styleguide work on matching
`feature/keycloak-sso-v1` branches. Fetch the authoritative upstream tags,
rebase onto an explicitly recorded stable baseline, and run the complete release
matrix before merging. Never resolve authentication-area conflicts using an
unreviewed blanket strategy.

## API pre-existing production files

- `composer.json`: registers the isolated plugin namespaces and the exact,
  reviewed HPKE/CBOR dependencies plus `ext-sodium` and the HPKE dependency's
  required `ext-gmp`. There is no repository
  mechanism that can install/autoload those requirements solely from the plugin
  directory. Conflict risk: medium near dependency/autoload blocks.
- `composer.lock`: locks only the approved direct dependencies and their
  transitive graph. Conflict risk: high on upstream dependency updates; resolve
  by regenerating from the rebased `composer.json`, then compare package
  versions, source references, and selection.
- `src/BaseSolutionBootstrapper.php`: one conditional feature-plugin
  registration is required because the application has no external plugin
  discovery mechanism. It keeps routes/listeners absent when disabled. Conflict
  risk: low to medium around upstream plugin registration.
- `config/Migrations/20260903*` through `20260906*`: new migration files only;
  they do not edit upstream migrations. Conflict risk: low, except timestamp or
  table-name collisions.

No core controller, GPGAuth, session, JWT, user table/finder, Pro SSO, edition,
or subscription implementation is modified.

## Browser-extension pre-existing production files

- `src/all/background_page/event/authEvents.js`: registers isolated
  Quick-Access-only controller messages. The controllers enforce the trusted
  worker boundary. Conflict risk: medium because upstream authentication events
  evolve frequently.
- `src/all/background_page/controller/account/updatePrivateKeyController.js`:
  activates the server-authoritative rotation barrier after local passphrase
  validation but before the persisted private-key update. No plugin/event hook
  exists at this exact security boundary. Conflict risk: high; manually preserve
  upstream rotation, Pro SSO-kit, passphrase-storage, and recovery-kit semantics.
- `package.json` and `package-lock.json`: add exact reviewed HPKE/CBOR
  dependencies. Conflict risk: high for the lock, low for the manifest.
- `jest.config.json`: maps the ESM CBOR entry for repository-native Jest. It is
  test configuration, not production behavior. Conflict risk: low.

All other extension production code is isolated under `controller/keycloakSso`,
`service/keycloakSso`, and `service/api/keycloakSso`. Generic OpenPGP and
authentication primitives remain unchanged.

## Styleguide pre-existing production files

- `ExtQuickAccess.js`: registers the management route because the styleguide has
  no feature-page plugin registry. Conflict risk: medium in the central route
  tree.
- `HomePage.js`: exposes the management entry only when site settings enable the
  plugin. Conflict risk: medium in Quick Access navigation.
- `LoginPage.js`: offers SSO login only when the plugin is enabled and a valid
  local browser-profile enrollment exists; successful recovery still calls the
  existing post-GPGAuth continuation. Conflict risk: high because upstream login
  and Pro SSO UX evolve here.
- `locales/en-UK/common.json`: contains the required localized UI text. Conflict
  risk: low but mechanically common.

The Keycloak management page and tests are new isolated files. Do not modify the
web-accessible `QuickAccess.js` wrapper unless separately approved.

## Rebase checks

After each upstream rebase, manually review changes to authentication,
GPGAuth/GPG-JWT, private-key update, Quick Access routing/login, worker message
boundaries, persistence, CSRF/session handling, Pro SSO, and edition/license
enforcement. Run frozen CBOR-vector hashes first; a mismatch is a stop condition,
not a conflict to normalize. Then run clean-install/upgrade migrations, feature
disablement, normal login, linking/enrollment/release, rotation, unlink, and the
full static/test matrices.
