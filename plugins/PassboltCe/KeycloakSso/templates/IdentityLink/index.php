<?php
/**
 * @var \App\View\AppView $this
 * @var string $csrfToken
 */
?>
<h1><?= __('Link Keycloak identity') ?></h1>
<p><?= __('Your normal Passbolt cryptographic login remains required.') ?></p>
<form method="post" action="/auth/keycloak/link/start">
    <input type="hidden" name="_csrfToken" value="<?= h($csrfToken) ?>">
    <button type="submit"><?= __('Continue to Keycloak') ?></button>
</form>
