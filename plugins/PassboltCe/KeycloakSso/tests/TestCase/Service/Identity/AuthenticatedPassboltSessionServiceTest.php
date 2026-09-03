<?php
declare(strict_types=1);

namespace Passbolt\KeycloakSso\Test\TestCase\Service\Identity;

use App\Model\Entity\User;
use App\Test\Factory\UserFactory;
use Cake\Http\ServerRequest;
use Passbolt\KeycloakSso\Error\Exception\IdentityLinkException;
use Passbolt\KeycloakSso\Service\Identity\AuthenticatedPassboltSessionService;
use Passbolt\KeycloakSso\Test\Lib\KeycloakSsoIntegrationTestCase;

final class AuthenticatedPassboltSessionServiceTest extends KeycloakSsoIntegrationTestCase
{
    public function testRejectsRequestIdentityWithoutServerSidePassboltSession(): void
    {
        $user = $this->activeUser();

        $this->expectException(IdentityLinkException::class);
        (new AuthenticatedPassboltSessionService())->getActiveUser(new ServerRequest(), $user->id);
    }

    public function testRejectsSessionAndRequestIdentityMismatch(): void
    {
        $sessionUser = $this->activeUser();
        $requestUser = $this->activeUser();
        $request = new ServerRequest();
        $request->getSession()->write('Auth.user.id', $sessionUser->id);

        $this->expectException(IdentityLinkException::class);
        (new AuthenticatedPassboltSessionService())->getActiveUser($request, $requestUser->id);
    }

    public function testAcceptsMatchingActiveServerSidePassboltSession(): void
    {
        $user = $this->activeUser();
        $request = new ServerRequest();
        $request->getSession()->write('Auth.user.id', $user->id);

        $result = (new AuthenticatedPassboltSessionService())->getActiveUser($request, $user->id);

        $this->assertSame($user->id, $result->id);
    }

    private function activeUser(): User
    {
        $user = UserFactory::make()->user()->active()->notDisabled()->persist();
        self::assertInstanceOf(User::class, $user);

        return $user;
    }
}
