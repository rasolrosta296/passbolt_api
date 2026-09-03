<?php
/** @var \App\View\AppView $this */
$csrfToken = (string)$this->getRequest()->getAttribute('csrfToken');
?>
<main class="page login">
    <h1><?= h(__('Login with Keycloak')) ?></h1>
    <p><?= h(__('Keycloak verifies your identity. Your Passbolt private key is still required afterwards.')) ?></p>
    <form method="post" action="/auth/keycloak/start" autocomplete="off">
        <input type="hidden" name="_csrfToken" value="<?= h($csrfToken) ?>">
        <button type="submit"><?= h(__('Continue to Keycloak')) ?></button>
    </form>
</main>
