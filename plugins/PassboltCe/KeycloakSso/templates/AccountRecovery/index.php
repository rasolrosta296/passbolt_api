<?php
/** @var string $csrfToken */
?>
<main class="page login">
    <h1><?= h(__('Set up this browser with Keycloak')) ?></h1>
    <p>
        <?= h(__('Keycloak verifies your identity. Your Passbolt recovery kit and passphrase are still required.')) ?>
    </p>
    <form method="post" action="/auth/keycloak/recover/start" autocomplete="off">
        <input type="hidden" name="_csrfToken" value="<?= h($csrfToken) ?>">
        <button type="submit"><?= h(__('Continue to Keycloak')) ?></button>
    </form>
    <p><a href="/recover"><?= h(__('Continue with email instead')) ?></a></p>
</main>
