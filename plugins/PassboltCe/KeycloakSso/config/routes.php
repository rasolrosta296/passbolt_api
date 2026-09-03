<?php
declare(strict_types=1);

use Cake\Routing\RouteBuilder;

/** @var \Cake\Routing\RouteBuilder $routes */
$routes->plugin('Passbolt/KeycloakSso', ['path' => '/auth/keycloak'], function (RouteBuilder $routes): void {
    $routes->setExtensions(['json']);

    $routes->connect('/', ['prefix' => 'Oidc', 'controller' => 'Authorization', 'action' => 'index'])
        ->setMethods(['GET']);
    $routes->connect('/start', ['prefix' => 'Oidc', 'controller' => 'Authorization', 'action' => 'start'])
        ->setMethods(['POST']);
});
