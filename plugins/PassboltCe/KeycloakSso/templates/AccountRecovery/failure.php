<?php
/** @var \App\View\AppView $this */
?>
<h1><?= h(__('Keycloak account verification failed')) ?></h1>
<p>
    <?= h(__('This browser could not be authorized for Passbolt account recovery. Start again or continue with email.')) ?>
</p>
<p><a href="/auth/keycloak/recover"><?= h(__('Try Keycloak again')) ?></a></p>
<p><a href="/recover"><?= h(__('Continue with email')) ?></a></p>
