# Dependency and advisory record

This record distinguishes protocol dependencies from unrelated production code
and build/test tooling. It must be refreshed from `composer audit` and
`npm audit` for every release candidate; an unrelated advisory is still a real
finding and must remain tracked by its owning upstream component.

## Cryptographic SSO production dependencies

| Repository | Dependency | Locked version | Purpose |
| --- | --- | --- | --- |
| API | `paragonie/hpke` | 0.8.0 | RFC 9180 HPKE sender used to seal KS to the ephemeral extension recipient. |
| API | `spomky-labs/cbor-php` | 3.3.4 | RFC 8949 deterministic CBOR parsing/encoding under the restricted protocol profile. |
| API | `ext-sodium` | platform | XChaCha20-Poly1305 server-share protection and best-effort memory clearing. |
| API | `ext-gmp` | platform | Required big-integer backend for the approved PHP HPKE/ECDSA dependency graph. |
| Extension | `@hpke/core` | 1.9.0 | RFC 9180 HPKE receiver. |
| Extension | `@hpke/common` | 1.10.1 | Transitive HPKE primitives required by `@hpke/core`. |
| Extension | `cborg` | 6.1.2 | Deterministic CBOR parsing/encoding under the restricted protocol profile. |

The release audit must explicitly record whether any advisory affects these
package dependencies. Do not replace or upgrade them automatically; any
cryptographic dependency or suite change requires separate protocol/security
review and refreshed cross-language vectors.

## Release-candidate audit snapshot

Audited with Node.js 22.23.1, npm 10.9.2, and the public npm advisory
service. The DDEV `composer audit --locked` reported no known advisories after
the package-scoped update of `composer/composer` from 2.10.2 to 2.10.3.
Neither `@hpke/core`, `@hpke/common`, `cborg`, `paragonie/hpke`, nor
`spomky-labs/cbor-php` was identified by these audits; their locked versions
and the approved protocol suite are unchanged.

The extension production dependency audit now reports zero findings. Two
targeted changes removed the previous KDBX import/export dependency findings:

| Dependency | Direct | Locked | Remediation and upstream impact |
| --- | --- | --- | --- |
| `@xmldom/xmldom` | No; via `kdbxweb` | 0.8.15 | Advance the existing upstream override by one patch version. Keep this as a single-line, independently droppable upstream delta until upstream adopts a patched release. |
| `fflate` | No; via `kdbxweb` | 0.7.5 | Update only the lock entry within upstream `kdbxweb`'s existing `^0.7.1` range; no manifest override or `kdbxweb` change. |
| `kdbxweb` | Yes | 2.1.1 | Unchanged. Its import/export tests and the full extension suite pass with the patched transitive packages. |

The extension's full dependency audit still reports seven high and four
moderate development/build findings: `@humanfs/node`, `addons-linter`,
`adm-zip`, `baseline-browser-mapping`, `browserslist`, `fast-uri`,
`firefox-profile`, `image-size`, `js-yaml`, `svgo`, and `web-ext`. The
styleguide production audit is clean; its full development/build audit reports
four high, three moderate, and two low findings: `@humanfs/node`,
`baseline-browser-mapping`, `browserslist`, `fast-uri`, `joi`, `js-yaml`,
`postcss-selector-parser`, `qs`, and `svgo`. These tools are outside the
runtime SSO path, but can affect release artifacts and remain upstream build
chain risks requiring separate review. No broad audit-fix or unrelated package
upgrade was applied.

## Classification rules

- **SSO reachable:** loaded into the API plugin or extension code paths used by
  CBOR, HPKE, envelope, OIDC, enrollment, release, or GPGAuth continuation.
- **Other production:** shipped in the API/extension but not reached by the SSO
  implementation. Remediation belongs to upstream dependency maintenance and
  must still be risk-assessed.
- **Development/build:** absent from the production runtime/bundle but able to
  affect builds, tests, linting, or release artifacts. A compromised build tool
  can still affect production output.

`npm audit fix`, broad Composer updates, and opportunistic dependency upgrades
are prohibited for this release candidate. Record direct/transitive status,
reachability, production bundling, available upstream remediation, and whether
the fix requires unrelated upgrades for every high or moderate finding.
