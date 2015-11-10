<?php

namespace Mtt\AppBundle\Security;

use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\User;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class HtpasswdUserProvider implements UserProviderInterface
{
    /**
     * @inheritDoc
     */
    public function loadUserByUsername($username)
    {
        $user = $this->getUserFromFile($username);
        if ($user !== false) {
            return new User($user['username'], $user['hash'], ['ROLE_USER']);
        }

        throw new UsernameNotFoundException(
            sprintf('Username "%s" does not exist.', $username)
        );
    }

    /**
     * @inheritDoc
     */
    public function refreshUser(UserInterface $user)
    {
        if (!$user instanceof User) {
            throw new UnsupportedUserException(
                sprintf('Instances of "%s" are not supported.', get_class($user))
            );
        }

        return $this->loadUserByUsername($user->getUsername());
    }

    /**
     * @inheritDoc
     */
    public function supportsClass($class)
    {
        return $class === 'Symfony\Component\Security\Core\User\User';
    }

    /**
     * @param $username
     * @return bool|array
     * @throws \Exception
     */
    protected function getUserFromFile($username)
    {
        $path = $this->filePath();
        $result = false;
        if (file_exists($path) && is_file($path)) {
            $f = fopen($path, 'r');
            while (($buffer = fgets($f, 512)) !== false) {
                $matches = [];
                if (preg_match('/^(.+):(.+)$/', $buffer, $matches) && $matches[1] === $username) {
                    $result = [
                        'username' => $matches[1],
                        'hash' => $matches[2],
                    ];
                    break;
                }
            }
            fclose($f);
        } else {
            throw new \Exception('file app/config/.users not found');
        }

        return $result;
    }

    /**
     * @return string
     */
    protected function filePath()
    {
        return realpath(__DIR__ . '/../../../../app/config/.users');
    }
}
