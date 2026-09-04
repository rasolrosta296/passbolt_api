<?php
/** @var string $message */
?>
<main>
    <h1><?= h(__('Keycloak authentication completed')) ?></h1>
    <p><?= h($message) ?></p>
    <p><?= h(__('Passbolt is not authenticated until the extension completes the normal cryptographic challenge.')) ?></p>
</main>
