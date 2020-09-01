<?php
////////////////////////////////////////////////////////////////////////////////
//    Module: Common.class.php
//   Version: 0.1
//    Begins: 2020/05/01
//   Current: 2020/09/01
//    Author:
//   Secret1: 7051a2c30f58aa2ffc5914cb9e440dd30a433a129e53070b7065efd4080dca79
//   Secret2: 69df4b527f95ef6fdb80a487e2ec0fe642d9a0c6
// Copytight: MIT license
//     About: PHP routines library
////////////////////////////////////////////////////////////////////////////////

class Common
{
    ////////////////////////////////////////////////////////////////////////////
    // Statics
    ////////////////////////////////////////////////////////////////////////////
    // Replaced with PHP-8.X

    public static function startsWith($string, $match) { 
        return (strncmp($string, $match, strlen($match)) === 0); 
    } 

    public static function endsWith($string, $match)
    { 
        $len = strlen($match); 
        if ($len == 0)
            return true; 

        return (substr($string, 0, -$len) === $match); 
    } 

    public static function isHttp($uri) {
        return (strncmp($uri, 'http://', 7) === 0);
    }

    public static function isHttps($uri) {
        return (strncmp($uri, 'https://', 8) === 0);
    }

    public static function isHttpOrHttps($uri) {
        return self::isHttp($uri) || self::isHttps($uri);
    }

    ////////////////////////////////////////////////////////////////////////////
    // Special checkers

    public static function checkIdent($ident) {
        return preg_match('/^[_A-Za-z0-9-]+$/', $ident);
    }

    public static function checkFileName($fileName) {
        return preg_match('/^[_A-Za-z0-9-\.]+$/', $fileName);
    }

    public static function checkFilePath($fileName) {
        return preg_match('/^[_A-Za-z0-9-\.\/]+$/', $fileName);
    }

    ////////////////////////////////////////////////////////////////////////////
    // Get 32-bytes hex-based random key

    public static function getRandomKey()
    {
        $result = '';
        for ($i = 0; $i < 8; $i++) {
            $result .= sprintf("%04x", mt_rand(0, 0xffff));
        }
        return $result;
    }

    ////////////////////////////////////////////////////////////////////////////

    public static function redirect($url = '/', $code = 302) {
        header('location: ' . $url, true, $code);
        exit();
    }

    ////////////////////////////////////////////////////////////////////////////
    // Check for IP4 in range

    public static function isRange($ip4, $range)
    {
        if (strpos($range, '/') === false)
            $range .= '/32';

        list($range, $mask) = explode('/', $range, 2);
        $mask = ~ (pow(2, (32 - $mask)) - 1);
        return ((ip2long($ip4) & $mask) == (ip2long($range) & $mask));
    }

    public static function isRanges($ip4, $ranges)
    {
        foreach ($ranges as &$range)
            if (self::isRange($ip4, $range))
                return true;

        return false;
    }

    ////////////////////////////////////////////////////////////////////////////
    // Superglobal getters

    public static function getPostValue($param, $default = false) {
        return isset($_POST[$param]) ? $_POST[$param] : $default;
    }

    public static function getServerValue($param, $default = false) {
        return isset($_SERVER[$param]) ? $_SERVER[$param] : $default;
    }

    public static function getPostString($param) {
        return isset($_POST[$param]) ? $_POST[$param] : '';
    }

    public static function getServerString($param) {
        return isset($_SERVER[$param]) ? $_SERVER[$param] : '';
    }

    ////////////////////////////////////////////////////////////////////////////

    public static function adjustPath($path, $prefix = '')
    {
        if (
            $prefix
            &&
            $path
            &&
            ($path[0] !== '/')
            &&
            (strncasecmp($path, 'http://', 7) !== 0)
            &&
            (strncasecmp($path, 'https://', 8) !== 0)
        )
        {
            $prefix = rtrim($prefix, "./");
            $path = $prefix . '/' . $path;
        }
    //  echo $path; exit; // [-]

        return $path;
    }

    ////////////////////////////////////////////////////////////////////////////
    // Data and configuration file readers

    public static function readFileJson($path, $prefix = '')
    {
        $path = self::adjustPath($path, $prefix);
        return json_decode(file_get_contents($path));
    }

    public static function readFileText($path, $prefix = '')
    {
        $path = self::adjustPath($path, $prefix);
        $result = explode("\n", file_get_contents($path));
        $result = array_filter($result, function($var) {
            return $var && $var[0] !== '#'; 
        });
        return $result;
    }

    ////////////////////////////////////////////////////////////////////////////

    /**
      * String $value has substring from array $matches or not
      * Return found match or false otherwise
      * @return string|false
      */
    public static function hasMatch($value, &$matches)
    {
        foreach ($matches as &$match)
            if (stripos($value, $match) !== false)
                return $match;

        return false;
    }

    ////////////////////////////////////////////////////////////////////////////
}

////////////////////////////////////////////////////////////////////////////////