<?php
/**
 * @var \App\View\AppView $this
 * @var string $csrfToken
 */
?>
<h1><?= __('Confirm Keycloak identity link') ?></h1>
<p><?= __('Link this freshly verified Keycloak identity to your current Passbolt account?') ?></p>
<form method="post" action="/auth/keycloak/link/confirm">
    <input type="hidden" name="_csrfToken" value="<?= h($csrfToken) ?>">
    <input type="hidden" name="confirmation" value="link_keycloak_identity">
    <button type="submit"><?= __('Link identity') ?></button>
</form>
