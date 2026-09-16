ARG PASSBOLT_BASE_IMAGE="passbolt/passbolt:5.15.0-1-ce@sha256:4006aec1bb8756ef921491b2a703dab6fbe10e0df38cb0ffd3e13b138bd7d63f"
ARG COMPOSER_IMAGE="composer:2.8.12@sha256:5248900ab8b5f7f880c2d62180e40960cd87f60149ec9a1abfd62ac72a02577c"

FROM ${COMPOSER_IMAGE} AS composer-bin

FROM ${PASSBOLT_BASE_IMAGE} AS vendor-builder

USER 0

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        php8.4-gmp=8.4.24-1~deb13u1 \
        unzip=6.0-29+deb13u1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=composer-bin /usr/bin/composer /usr/local/bin/composer

WORKDIR /build

COPY composer.json composer.lock ./
COPY src ./src
COPY plugins ./plugins

RUN composer install \
        --optimize-autoloader \
        --no-dev \
        --no-interaction \
        --no-progress \
        --no-scripts \
        --prefer-dist \
    && composer check-platform-reqs --no-dev

USER 33:33

FROM ${PASSBOLT_BASE_IMAGE}

ARG BUILD_DATE=""
ARG VCS_REF=""
ARG VERSION=""

LABEL org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="https://github.com/rasolrosta296/passbolt_api" \
      org.opencontainers.image.title="Passbolt CE with Keycloak cryptographic SSO" \
      org.opencontainers.image.version="${VERSION}"

USER 0

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        bash=5.2.37-2+b9 \
        php8.4-gmp=8.4.24-1~deb13u1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=vendor-builder /build/vendor /usr/share/php/passbolt/vendor
COPY plugins/PassboltCe/KeycloakSso/config /usr/share/php/passbolt/plugins/PassboltCe/KeycloakSso/config
COPY plugins/PassboltCe/KeycloakSso/src /usr/share/php/passbolt/plugins/PassboltCe/KeycloakSso/src
COPY plugins/PassboltCe/KeycloakSso/templates /usr/share/php/passbolt/plugins/PassboltCe/KeycloakSso/templates
COPY src/BaseSolutionBootstrapper.php /usr/share/php/passbolt/src/BaseSolutionBootstrapper.php
COPY src/Middleware/ContentSecurityPolicyExtension.php /usr/share/php/passbolt/src/Middleware/ContentSecurityPolicyExtension.php
COPY src/Middleware/ContentSecurityPolicyMiddleware.php /usr/share/php/passbolt/src/Middleware/ContentSecurityPolicyMiddleware.php
COPY --chown=root:www-data --chmod=0640 config/Migrations/20260903120000_CreateKeycloakSsoTransactions.php /etc/passbolt/Migrations/
COPY --chown=root:www-data --chmod=0640 config/Migrations/20260904120000_CreateKeycloakSsoIdentities.php /etc/passbolt/Migrations/
COPY --chown=root:www-data --chmod=0640 config/Migrations/20260905120000_CreateKeycloakSsoCryptoEnrollments.php /etc/passbolt/Migrations/
COPY --chown=root:www-data --chmod=0640 config/Migrations/20260906120000_CreateKeycloakSsoRotationBarriers.php /etc/passbolt/Migrations/

RUN chown -R root:www-data /usr/share/php/passbolt/plugins/PassboltCe/KeycloakSso \
    && find /usr/share/php/passbolt/plugins/PassboltCe/KeycloakSso -type d -exec chmod 0750 {} + \
    && find /usr/share/php/passbolt/plugins/PassboltCe/KeycloakSso -type f -exec chmod 0640 {} +

WORKDIR /usr/share/php/passbolt

RUN php -r 'exit(extension_loaded("gmp") && extension_loaded("sodium") ? 0 : 1);' \
    && php -r 'require "/usr/share/php/passbolt/vendor/autoload.php"; exit(class_exists("Passbolt\\KeycloakSso\\KeycloakSsoPlugin") ? 0 : 1);' \
    && php -r 'require "/usr/share/php/passbolt/vendor/autoload.php"; exit(is_a("Cake\\ORM\\Query\\SelectQuery", "Cake\\ORM\\Query", true) ? 0 : 1);' \
    && /usr/bin/bash -c 'set -euo pipefail; test -n "$BASH_VERSION"' \
    && test ! -e /usr/share/php/passbolt/vendor/phpunit
