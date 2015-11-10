<?php

namespace Mtt\AppBundle\Security;

class HtpassdReader
{
    /**
     * @param $username
     * @return bool|array
     * @throws \Exception
     */
    public static function getUser($username)
    {
        $path = self::filePath();
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
    public static function filePath()
    {
        return realpath(__DIR__ . '/../../../../app/config/.users');
    }
}
