<?php
////////////////////////////////////////////////////////////////////////////////
//    Module: Protector.class.php
//   Version: 0.1
//    Begins: 2020/05/01
//   Current: 2020/09/01
//    Author:
//   Secret1: 7051a2c30f58aa2ffc5914cb9e440dd30a433a129e53070b7065efd4080dca79
//   Secret2: 69df4b527f95ef6fdb80a487e2ec0fe642d9a0c6
// Copytight: MIT license
//     About: PHP-based web application protector script
//   Require: JSON-configuration file 'protector.json'
//          : Common.class.php library
////////////////////////////////////////////////////////////////////////////////

class Protector
{
    ////////////////////////////////////////////////////////////////////////////
    // Variables

//  private $app;

    private $path;
    private $logpath;

    private $settings;

    private $timezone;

    private $ip;
    private $uri;
    private $userAgent;
    private $referer;

    ////////////////////////////////////////////////////////////////////////////
    // Construct

    private function __construct($path)
    {
        $this->path      = $path;
        $this->settings  = Common::readFileJson('protector.json', $path);

        $this->logpath   = $this->settings->log
            ? Common::adjustPath($this->settings->log, $path)
            : false;

        $this->timezone  = isset($this->settings->timezone)
            ? $this->settings->timezone
            : 'UTC';

        $this->ip        = $this->getClientIp();
        $this->uri       = Common::getServerString('REQUEST_URI');
        $this->userAgent = Common::getServerString('HTTP_USER_AGENT');
        $this->referer   = Common::getServerString('HTTP_REFEFER');
    }

    ////////////////////////////////////////////////////////////////////////////
    // Get client ip

    private function getClientIp()
    {
        return isset($_SERVER['HTTP_CF_CONNECTING_IP'])
            ? $_SERVER['HTTP_CF_CONNECTING_IP']
            : $_SERVER['REMOTE_ADDR'];
    }

    ////////////////////////////////////////////////////////////////////////////
    // Init settings

    private function isEnabled() {
        return $this->settings->enabled;
    }

    private function isWelcome() {
        return $this->settings->welcome;
    }

    ////////////////////////////////////////////////////////////////////////////
    // Match checkers

    private function isIp4(&$ranges) {
        return Common::isRanges($this->ip, $ranges);
    }

    private function isUri(&$matches) {
        return Common::hasMatch($this->uri, $matches);
    }

    private function isUserAgent(&$matches) {
        return Common::hasMatch($this->userAgent, $matches);
    }

    ////////////////////////////////////////////////////////////////////////////
    // $start = 08:00
    // $stop = 20:00
    // Then
    // true from 08:00 to 20:00
    // false from 20:00 to 08:00

    private function isTime(&$times)
    {
        foreach ($times as &$time)
        {
            if (!isset($time->start))
                continue;
            if (!isset($time->stop))
                continue;

            $start = $time->start;
            $stop = $time->stop;

            // 'UTC' by default
            $timezone = isset($time->timezone)
                ? $time->timezone
                : $this->timezone;

            $date = new DateTime('now', new DateTimeZone($timezone));
            $hour = intval($date->format('H'));

            return $start < $stop
                ? ($hour >= $start) && ($hour < $stop)
                : ($hour >= $start) || ($hour < $stop);
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // Ip in region

    private function isLocation(&$locations)
    {
        $info = file_get_contents('http://www.geoplugin.net/json.gp?ip=' . $this->ip);        
        $info = json_decode($info);
        $country = $info->geoplugin_countryCode;
        $region = $info->geoplugin_regionCode;

        foreach ($locations as &$location)
            if (($location->country == $country) && ($location->region == $region))
                return true;
 
        return false;
    }

    ////////////////////////////////////////////////////////////////////////////
    // Log

    private function getRuleActionsAsString(&$rule)
    {
        if (!isset($rule->actions))
            return '';

        $actions = array_filter($rule->actions, function($action) {
            return $action != 'log';
        });
        return (' ' . implode('/', $actions));
    }

    private function log(&$rule)
    {
        if (is_writeable($this->logpath) == false)
            return;

        $timezone = isset($this->timezone)
            ? $this->timezone
            : 'UTC';

        $date = (new DateTime('now', new DateTimeZone($timezone)))
        //  ->format('Y-m-d H:i:s GMT P e');
            ->format('Y-m-d H:i:s P');

        $name = isset($rule->name)
            ? $rule->name
            : 'unknown';

        $actions = $this->getRuleActionsAsString($rule);

        $comment = isset($rule->comment)
            ? (' ' . $rule->comment)
            : '';

        $ip = $this->ip;

        $uri = $this->uri;

        $userAgent = $this->userAgent;

        $referer = $this->referer
            ? (' "' . $this->referer . '"')
            : '';

        $data = "$date $name:$actions $ip \"$uri\" \"$userAgent\"$referer$comment\n";
        file_put_contents($this->logpath, $data, FILE_APPEND);
    }

    ////////////////////////////////////////////////////////////////////////////
    // Check rule

    private function getRuleData(&$rule)
    {
        $name = $rule->name;

        $data = isset($rule->data)
            ? $rule->data
            : (isset($rule->file)
                ? Common::readFileText($rule->file, $this->path)
                : ($name && isset($this->settings->{$name})
                    ? $this->settings->{$name}
                    : null
                )
            );
        if ($data && (!is_array($data)))
            $data = array($data);

        return $data;
    }

    private function checkRule(&$rule)
    {
        $invert = isset($rule->invert)
            ? $rule->invert
            : false;

        $data = $this->getRuleData($rule);

        $result = false;
        switch ($rule->type)
        {
            case 'ip4':
                $result = $this->isIp4($data);
                break;
            case 'uri':
                $result = $this->isUri($data);
                break;
            case 'time':
                $result = $this->isTime($data);
                break;
            case 'user-agent':
                $result = $this->isUserAgent($data);
                break;
            case 'location':
                $result = $this->isTime($data);
                break;
        }
        return $invert xor $result;
    }

    ////////////////////////////////////////////////////////////////////////////
    // Check rules

    public function checkRules()
    {
        $rules = &$this->settings->rules;

        foreach ($rules as &$rule)
        {
            if (isset($rule->enabled) && ($rule->enabled == false))
                continue;

            if (
                (isset($rule->type) == false)
                ||
                $this->checkRule($rule)
            )
            {
                $actions = is_array($rule->actions)
                    ? $rule->actions
                    : array($rule->actions);

                foreach ($actions as &$action)
                {
                    if ($action == 'pass')
                        break;
                    if ($action == 'log')
                        $this->log($rule);
                    if ($action == 'allow')
                        return true;
                    if ($action == 'deny')
                        return false;
                    if ($action == 'default')
                        return $this->isWelcome();
                    if ($action == 'exit')
                        exit();
                    if ($action == 'redirect')
                        Common::redirect(
                            isset($rule->url) ? $rule->url : '/',
                            isset($rule->code) ? $rule->code : 302
                        );
                }
            }
        }

        return $this->isWelcome();
    }

    ////////////////////////////////////////////////////////////////////////////
    // Dummy

    private function onDeny()
    {
        if ($this->settings->onDeny) {
            include($this->settings->onDeny);
            exit();
        }
    }

    private function onAllow()
    {
        if ($this->settings->onAllow) {
            include($this->settings->onAllow);
            exit();
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // Main routine

    private function main()
    {
        if ($this->isEnabled() == false)
            return true;

        $welcome = $this->checkRules();

        if ($welcome) {
            $this->onAllow();
        } else {
            $this->onDeny();
        }

        return $welcome;
    }

    ////////////////////////////////////////////////////////////////////////////
    // Runner

    /**
     * Return
     * true if allow
     * false if deny
     * @return boolean
     */
    public static function execute($path)
    {
        return (new Protector($path))->main();
    }

    ////////////////////////////////////////////////////////////////////////////
}

////////////////////////////////////////////////////////////////////////////////