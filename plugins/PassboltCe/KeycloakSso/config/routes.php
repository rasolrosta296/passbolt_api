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
    $routes->connect('/callback', ['prefix' => 'Oidc', 'controller' => 'Callback', 'action' => 'callback'])
        ->setMethods(['GET']);
    $routes->connect('/result', ['prefix' => 'Oidc', 'controller' => 'Result', 'action' => 'result'])
        ->setMethods(['GET']);
    $routes->connect('/error', ['prefix' => 'Oidc', 'controller' => 'Result', 'action' => 'failure'])
        ->setMethods(['GET']);
});
