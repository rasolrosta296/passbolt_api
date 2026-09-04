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
    $routes->connect('/link', ['controller' => 'IdentityLink', 'action' => 'index'])
        ->setMethods(['GET']);
    $routes->connect('/link/start', ['controller' => 'IdentityLink', 'action' => 'start'])
        ->setMethods(['POST']);
    $routes->connect('/link/confirm', ['controller' => 'IdentityLink', 'action' => 'confirm'])
        ->setMethods(['GET']);
    $routes->connect('/link/confirm', ['controller' => 'IdentityLink', 'action' => 'confirmPost'])
        ->setMethods(['POST']);
    $routes->connect('/unlink', ['controller' => 'IdentityLink', 'action' => 'unlink'])
        ->setMethods(['POST']);
    $routes->connect('/crypto/enroll/start', ['controller' => 'CryptoSso', 'action' => 'startEnrollment'])
        ->setMethods(['POST']);
    $routes->connect('/crypto/enroll', ['controller' => 'CryptoSso', 'action' => 'enroll'])
        ->setMethods(['POST']);
    $routes->connect('/crypto/login/start', ['controller' => 'CryptoSso', 'action' => 'startLogin'])
        ->setMethods(['POST']);
    $routes->connect('/crypto/release', ['controller' => 'CryptoSso', 'action' => 'release'])
        ->setMethods(['POST']);
    $routes->connect('/crypto/rotation/start', ['controller' => 'CryptoSso', 'action' => 'startRotation'])
        ->setMethods(['POST']);
    $routes->connect('/crypto/rotation/complete', ['controller' => 'CryptoSso', 'action' => 'completeRotation'])
        ->setMethods(['POST']);
    $routes->connect('/crypto/rotation/fail', ['controller' => 'CryptoSso', 'action' => 'failRotation'])
        ->setMethods(['POST']);
    $routes->connect('/crypto/complete', ['controller' => 'CryptoSso', 'action' => 'complete'])
        ->setMethods(['GET']);
});
