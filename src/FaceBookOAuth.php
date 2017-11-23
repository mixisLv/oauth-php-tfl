<?php

namespace mixisLv\OAuth;

use JacobKiers\OAuth\OAuthException;

/**
 * FaceBook OAuth class
 *
 * A class handling the OAuth verification procedure for Facebook
 */
class FaceBookOAuth {

    private $properties = null;
    private $token      = null;
    private $errorMsg   = null;

    public function __construct($properties) {
        $this->properties = $properties;
    }

    public function __get($name) {
        switch($name) {
            case 'authorizationUrl':
                $url = $this->properties['url'] .'authorize?client_id=' .$this->properties['clientId'] .'&redirect_uri=' .$this->properties['redirectUri'];
                if(count($this->properties['scope'])) {
                    $url .= '&scope=' .implode(',', $this->properties['scope']);
                }
                return $url;

                break;
            case 'token':
                if(!$this->token && isset($_GET['code'])) {
                    try {
                        $file = $this->properties['url'] .'access_token?client_id=' .$this->properties['clientId'] .'&redirect_uri=' .($this->properties['redirectUri']) .'&client_secret=' .$this->properties['clientSecret'] .'&code=' .$_GET['code'];
                        $this->token = file_get_contents($file);
                        if ($this->token === false) {
                            // throw the exception or just deal with it
                            throw new OAuthException('Failed to open ' . $file);
                        }
                    } catch (OAuthException $e) {
                        throw new OAuthException("Can\'t connect to Facebook");
                    }
                }
                return $this->token;
                break;
            case 'error':
                if(isset($_GET['error_reason'])) {
                    return $_GET['error_reason'];
                }
                if($this->errorMsg) {
                    return $this->errorMsg;
                }
                break;
        }
        return null;
    }
}
