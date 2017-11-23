<?php

namespace mixisLv\OAuth;

use JacobKiers\OAuth\SignatureMethod\HmacSha1;
use JacobKiers\OAuth\Consumer\Consumer;
use JacobKiers\OAuth\Request\Request;

/**
 * LinkedIn OAuth class
 *
 * A class handling the OAuth verification procedure for LinkedIn
 */
class LinkedInOAuth {
    // Contains the last HTTP status code returned
    private $http_status;

    // Contains the last API call
    private $last_api_call;

    //Response format
    public $format = 'json';

    // Decode returned json data
    public $decode_json = true;

    // The base of the LinkedIn OAuth URLs
    public $LINKEDIN_API_ROOT = 'https://api.linkedin.com/';

    public $request_options = array();

    /**
     * Set API URLS
     */
    function accessTokenURL()  { return 'https://api.linkedin.com/uas/oauth/accessToken'; }
    function authorizeURL()    { return 'https://api.linkedin.com/uas/oauth/authorize'; }
    function requestTokenURL() { return 'https://api.linkedin.com/uas/oauth/requestToken'; }


    /**
    * Debug helpers
    */
    function lastStatusCode() { return $this->http_status; }
    function lastAPICall() { return $this->last_api_call; }

    function __construct($consumer_key, $consumer_secret, $oauth_token = NULL, $oauth_token_secret = NULL) {
        $this->sha1_method = new HmacSha1();
        $this->consumer = new Consumer($consumer_key, $consumer_secret);
        if (!empty($oauth_token) && !empty($oauth_token_secret)) {
            $this->token = new Consumer($oauth_token, $oauth_token_secret);
        } else {
            $this->token = NULL;
        }
    }

    /**
    * Get a request_token from LinkedIn
    *
    * @return array key/value array containing oauth_token and oauth_token_secret
    */
    function getRequestToken($oauth_callback = NULL) {
        if (!empty($oauth_callback)) {
            $this->request_options['oauth_callback'] = $oauth_callback;
        }
        $requestUrl = $this->requestTokenURL();
        $r = $this->oAuthRequest($requestUrl, $this->request_options, 'GET');
        $token = $this->oAuthParseResponse($r);
        $this->token = new Consumer($token['oauth_token'], $token['oauth_token_secret'], $oauth_callback);
        return $token;
    }

    /**
    * Parse a URL-encoded OAuth response
    *
    * @return array key/value
    */
    function oAuthParseResponse($responseString) {
        $r = array();
        foreach (explode('&', $responseString) as $param) {
            $pair = explode('=', $param, 2);
            if (count($pair) != 2) continue;
            $r[urldecode($pair[0])] = urldecode($pair[1]);
        }
        return $r;
    }

    /**
    * Get the authorize URL
    *
    * @return string
    */
    function getAuthorizeURL($token, $callbackurl=null) {
        if (is_array($token)) $token = $token['oauth_token'];
        $result = $this->authorizeURL();
        $result .= '?oauth_token=' . $token;
        //$result .= '&oauth_callback=' . urlencode($callbackurl);

        return $result;
    }

    /**
    * Exchange the request token and secret for an access token and
    * secret, to sign API calls.
    *
    * @returns array("oauth_token" => the access token,
    *                "oauth_token_secret" => the access secret)
    */
    function getAccessToken($verifier) {
        $r = $this->oAuthRequest($this->accessTokenURL(), array('oauth_verifier' => $verifier), 'GET');
        error_log('$r: '.print_r($r, true));
        $token = $this->oAuthParseResponse($r);
        $this->token = new Consumer($token['oauth_token'], $token['oauth_token_secret']);
        return $token;
    }


  /**
   * GET wrapper for oAuthRequest.
   */
  function get($url, $args = array()) {
    $response = $this->oAuthRequest($url, $args, 'GET');
    if ($this->format === 'json' && $this->decode_json) {
      return json_decode($response);
    }
    return $response;
  }

    /**
    * Format and sign an OAuth / API request
    */
    function oAuthRequest($url, $args = array(), $method = NULL) {
        if (empty($method)) $method = empty($args) ? "GET" : "POST";
        $args['format'] = $this->format;
        $req = Request::fromConsumerAndToken($this->consumer, $this->token, $method, $url, $args);
        $req->signRequest($this->sha1_method, $this->consumer, $this->token);
        switch ($method) {
            case 'GET': return $this->http($req->toUrl());
            case 'POST': return $this->http($req->getNormalizedHttpUrl(), $req->toPostdata());
        }
    }

    /**
    * Make an HTTP request
    *
    * @return string API results
    */
    function http($url, $post_data = null) {
        //error_log("Calling '$url'");
        $ch = curl_init();
        if (defined("CURL_CA_BUNDLE_PATH")) curl_setopt($ch, CURLOPT_CAINFO, CURL_CA_BUNDLE_PATH);
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 30);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, TRUE);
        //////////////////////////////////////////////////
        ///// Set to 1 to verifySSL Cert            //////
        //////////////////////////////////////////////////
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
        if (isset($post_data)) {
            curl_setopt($ch, CURLOPT_POST, 1);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $post_data);
        }
        $response = curl_exec($ch);
        $this->http_status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $this->last_api_call = $url;
        curl_close ($ch);
        return $response;
    }

    function getUserByOAuth2AccessToken($resource, $accessToken) {
        $opts = array(
            'http'=>array(
                'method' => "GET",
                'header' => "Authorization: Bearer " . $accessToken . "\r\n" . "x-li-format: json\r\n"
            )
        );

        // Need to use HTTPS
        $url = 'https://api.linkedin.com' . $resource;

        // Tell streams to make a (GET, POST, PUT, or DELETE) request
        // And use OAuth 2 access token as Authorization
        $context = stream_context_create($opts);

        // Hocus Pocus
        $response = file_get_contents($url, false, $context);

        // Native PHP object, please
        return json_decode($response);
    }

}
