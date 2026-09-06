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

Audited with Node.js 22.23.1, npm 10.9.8, and the public npm advisory
service. `composer audit` reported no known advisories. Neither `@hpke/core`,
`@hpke/common`, `cborg`, `paragonie/hpke`, nor `spomky-labs/cbor-php` was
identified by these audits.

The extension production dependency graph has three moderate findings:

| Dependency | Direct | Locked | Production/reachability | Remediation disposition |
| --- | --- | --- | --- | --- |
| `@xmldom/xmldom` | No; via `kdbxweb` | 0.8.14 | Bundled for KDBX XML handling; not reachable from Keycloak SSO. GHSA-6gmq-8vp8-gcm6 applies. | npm proposes changing `kdbxweb`; evaluate with upstream KDBX tests instead of applying automatically. |
| `fflate` | No | 0.7.4 | Bundled archive parser; not reachable from Keycloak SSO. GHSA-px8p-9vwx-vf98 applies to malformed ZIP64 input. | A patched release exists; update through normal upstream dependency review. |
| `kdbxweb` | Yes | 2.1.1 | Bundled for KeePass import/export; not reachable from Keycloak SSO, but it pulls the vulnerable XML serializer. | npm's offered `2.1.0` change is not an acceptable blind audit fix; coordinate an upstream-compatible remediation. |

The extension's full graph additionally reports five high and one moderate
development/build findings (`browserslist` 4.28.1, `fast-uri` 3.1.5,
`image-size` 2.0.2, `addons-linter` 10.7.0, `web-ext` 10.4.0, and
`@humanfs/node` 0.16.7). They are not production runtime dependencies or SSO
runtime paths, but can affect release tooling. The offered fixes include
unrelated or backward dependency changes and were not applied.

The styleguide production dependency audit is clean. Its full development/build
graph reports two high, two moderate, and one low finding: `browserslist`
4.28.2, `fast-uri` 3.1.5, `@humanfs/node` 0.16.7, `qs` 6.15.3, and
`postcss-selector-parser` 7.1.1. None is an SSO runtime dependency; they remain
build-chain risks for upstream remediation.

These findings are not described as harmless merely because the Keycloak SSO
path does not reach them. The three extension production findings require an
explicit release risk acceptance or upstream remediation before production.

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
