# Keycloak SSO production image

This image is a narrow overlay on the official standard Passbolt CE 5.15.0
image. It keeps the official rootful image's entrypoint, services, runtime
user, ports, and package layout while adding only the reviewed Keycloak SSO
plugin, its two generic core extension points, its four migrations, locked
production Composer dependencies, and the GMP runtime extension required by
the HPKE implementation. GNU Bash is an explicit pinned runtime dependency for
approved operational and init scripts.

The base image and Composer build image are pinned by digest. Updating either
digest is a security-sensitive maintenance task and must be reviewed together
with the matching upstream Passbolt release. The added GMP Debian package is
also pinned to the version shipped for that base; it must be reviewed and
updated with the base image rather than silently drifting between rebuilds.

Composer's optimized PSR-4 fallback must remain enabled. Do not generate an
authoritative classmap: CakePHP's backwards-compatible `Cake\ORM\Query`
alias is loaded through PSR-4 fallback and is required by the Passbolt 5.15
source. The image build verifies this compatibility alias before publishing.

## Build

From the API repository root:

```sh
docker build \
  --file docker/keycloak-sso/Dockerfile \
  --tag passbolt-api-keycloak-sso:local \
  --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --build-arg VCS_REF="$(git rev-parse HEAD)" \
  --build-arg VERSION="local" \
  .
```

No secret is required or accepted at build time. Supply Passbolt and Keycloak
configuration only at runtime. In particular, never bake the OIDC client
secret, transaction encryption key, server-share KEK key ring, Passbolt GPG
private key, JWT private key, database password, or TLS private key into an
image layer.

## Release image

The release workflow publishes a multi-architecture image to:

```text
ghcr.io/rasolrosta296/passbolt-api-keycloak-sso
```

Release tags must have the form `keycloak-sso-v1.2.3-rc.4`. Deploy the image by
its immutable manifest digest rather than a mutable tag.

The official Passbolt entrypoint runs installation or migrations on startup.
For a multi-replica production rollout, coordinate migration execution so only
one migration actor runs before application replicas are updated. This image
does not contain cluster deployment logic.

## Upgrade rule

The overlay is valid only while its pinned official image represents the same
Passbolt API version as this branch. For each upstream update:

1. rebase the API branch onto the new upstream tag;
2. run the complete API and Keycloak SSO test gates;
3. update and review the official image digest;
4. rebuild and run the image smoke checks;
5. perform the non-production live authentication gates;
6. publish a new immutable image tag and digest.
