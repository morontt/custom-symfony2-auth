<?php

namespace Mtt\AppBundle\Security;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\SimpleFormAuthenticatorInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\User;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class HtpasswdAuthenticator implements SimpleFormAuthenticatorInterface
{
    /**
     * @param TokenInterface $token
     * @param UserProviderInterface $userProvider
     * @param $providerKey
     * @return UsernamePasswordToken
     */
    public function authenticateToken(TokenInterface $token, UserProviderInterface $userProvider, $providerKey)
    {
        try {
            /* @var User $user */
            $user = $userProvider->loadUserByUsername($token->getUsername());
        } catch (UsernameNotFoundException $e) {
            throw new AuthenticationException('Invalid username or password');
        }

        $passwordValid = $this->checkPassword($user, $token->getCredentials());

        if ($passwordValid) {
            return new UsernamePasswordToken(
                $user,
                $user->getPassword(),
                $providerKey,
                $user->getRoles()
            );
        }

        throw new AuthenticationException('Invalid username or password');
    }

    /**
     * @param TokenInterface $token
     * @param $providerKey
     * @return bool
     */
    public function supportsToken(TokenInterface $token, $providerKey)
    {
        return $token instanceof UsernamePasswordToken && $token->getProviderKey() === $providerKey;
    }

    /**
     * @param Request $request
     * @param $username
     * @param $password
     * @param $providerKey
     * @return UsernamePasswordToken
     */
    public function createToken(Request $request, $username, $password, $providerKey)
    {
        return new UsernamePasswordToken($username, $password, $providerKey);
    }

    /**
     * @param User $user
     * @param $credentials
     * @return bool
     */
    protected function checkPassword(User $user, $credentials)
    {
        $password = $user->getPassword();

        if (strpos($password, '{SHA}') === 0) {
            return substr($password, 5) === base64_encode(sha1($credentials, true));
        }

        $matches = [];
        if (preg_match('/^\$apr1\$(.+)\$(.+)$/', $password, $matches)) {
            return $this->md5Apr($credentials, $matches[1]) === $matches[2];
        }

        if (strlen($password) == 13) {
            return $password === crypt($credentials, substr($password, 0, 2));
        }

        return false;
    }

    /**
     * Apache-specific algorithm MD5 (APR)
     * http://www.lsdeex.ru/archives/199
     *
     * @param $password
     * @param $salt
     * @return string
     */
    protected function md5Apr($password, $salt)
    {
        $len = strlen($password);
        $text = $password . '$apr1$' . $salt;
        $bin = pack("H32", md5($password . $salt . $password));

        for ($i = $len; $i > 0; $i -= 16) {
            $text .= substr($bin, 0, min(16, $i));
        }

        for ($i = $len; $i > 0; $i >>= 1) {
            $text .= ($i & 1) ? chr(0) : $password{0};
        }

        $bin = pack("H32", md5($text));

        for ($i = 0; $i < 1000; $i++) {
            $new = ($i & 1) ? $password : $bin;

            if ($i % 3) {
                $new .= $salt;
            }

            if ($i % 7) {
                $new .= $password;
            }

            $new .= ($i & 1) ? $bin : $password;
            $bin = pack("H32", md5($new));
        }

        $tmp = '';

        for ($i = 0; $i < 5; $i++) {
            $k = $i + 6;
            $j = $i + 12;

            if ($j == 16) {
                $j = 5;
            }

            $tmp = $bin[$i] . $bin[$k] . $bin[$j] . $tmp;
        }

        $tmp = chr(0) . chr(0) . $bin[11] . $tmp;
        $tmp = strtr(
            strrev(substr(base64_encode($tmp), 2)),
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwx  yz0123456789+/",
            "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn  opqrstuvwxyz"
        );

        return $tmp;
    }
}
