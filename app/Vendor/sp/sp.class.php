<?php
class SPOClient {
    /**
     * External Security Token Service for SPO
     * @var mixed
     */
    private static $stsUrl = 'https://login.microsoftonline.com/extSTS.srf';
    /**
     * Form Url to submit SAML token
     * @var string
     */
    private static $signInPageUrl = '/_forms/default.aspx?wa=wsignin1.0';
    /**
     * SharePoint Site url
     * @var string
     */
    
    
   
    public $url;
    /**
     * SPO Auth cookie
     * @var mixed
     */
    public $FedAuth;
    /**
     * SPO Auth cookie
     * @var mixed
     */
    public $rtFa;
    /**
     * Form Digest
     * @var string
     */
    public $formDigest;
    /**
     * SSL Version
     * @var int
     */
    protected $sslVersion = null;
    /**
     * Class constructor
     * @param string $url
     * @throws Exception
     */
    public function __construct($url)
    {
        if (!function_exists('curl_init')) {
            throw new \Exception('CURL module not available! SPOClient requires CURL. See http://php.net/manual/en/book.curl.php');
        }
        $this->url = $url;
    }
    public function setSslVersion($sslVersion)
    {
        if (!is_int($sslVersion)) {
            throw new \InvalidArgumentException("SSL Version must be an integer");
        }
        $this->sslVersion = $sslVersion;
    }
    /**
     * SPO sign-in
     * @param mixed $username
     * @param mixed $password
     */
    public function signIn($username, $password)
    {
        $token = $this->requestToken($username, $password);
        $header = $this->submitToken($token);
        $this->saveAuthCookies($header);
        $contextInfo = $this->requestContextInfo();
        $this->saveFormDigest($contextInfo);
    }
    /**
     * Init Curl with the default parameters
     * @return    [type]    [description]
     */
    protected function initCurl($url)
    {
        $ch = curl_init();
        if (!is_null($this->sslVersion)) {
            curl_setopt($ch, CURLOPT_SSLVERSION, $this->sslVersion);
        }
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_URL, $url);
        return $ch;
    }
    /**
     * Request the Context Info
     * @return mixed
     */
    protected function requestContextInfo()
    {
        $options = array(
         'url' => $this->url . "/_api/contextinfo",
         'method' => 'POST'
        );
        $data = $this->request($options, false);
        return $data->d->GetContextWebInformation;
    }
    /**
     * Save the SPO Form Digest
     * @param mixed $contextInfo
     */
    protected function saveFormDigest($contextInfo)
    {
        $this->formDigest = $contextInfo->FormDigestValue;
    }
    /**
     * Request the SharePoint REST endpoint
     * @param mixed $options
     * @throws Exception
     * @return mixed
     */
    protected function request($options, $pass_form_digest = true)
    {
        $data = array_key_exists('data', $options) ? json_encode($options['data']) : '';
        $headers = array(
            'Accept: application/json; odata=verbose',
            'Content-type: application/json; odata=verbose',
            'Cookie: FedAuth=' . $this->FedAuth . '; rtFa=' . $this->rtFa,
            'Content-length:' . strlen($data)
        );
        // Include If-Match header if etag is specified
        if (array_key_exists('etag', $options)) {
            $headers[] = 'If-Match: ' . $options['etag'];
        }
        // Include X-RequestDigest header if formdigest is specified
        if (array_key_exists('formdigest', $options)) {
            $headers[] = 'X-RequestDigest: ' . $options['formdigest'];
        } elseif ($pass_form_digest == true && ($options['method'] == 'POST' ||$options['method'] == 'DELETE')) {
            $contextInfo = $this->requestContextInfo();
            $headers[] = 'X-RequestDigest: ' . $contextInfo->FormDigestValue;
        }
        // Include X-Http-Method header if xhttpmethod is specified
        if (array_key_exists('xhttpmethod', $options)) {
            $headers[] = 'X-Http-Method: ' . $options['xhttpmethod'];
        }
        $ch = $this->initCurl($options['url']);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        if ($options['method'] != 'GET') {
            curl_setopt($ch, CURLOPT_POST, 1);
            if (array_key_exists('data', $options)) {
                curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
            }
        }
        $result = curl_exec($ch);
        if ($result === false) {
            throw new \Exception(curl_error($ch));
        }
        curl_close($ch);
        $result = json_decode($result);
        if (isset($result->error)) {
            throw new \RuntimeException("SharePoint Error: " . $result->error->message->value);
        }
        return $result;
    }
    /**
     * Get the FedAuth and rtFa cookies
     * @param mixed $token
     * @throws Exception
     */
    protected function submitToken($token)
    {
        $urlinfo = parse_url($this->url);
        $url =  $urlinfo['scheme'] . '://' . $urlinfo['host'] . self::$signInPageUrl;
        $ch = $this->initCurl($url);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $token);
        curl_setopt($ch, CURLOPT_HEADER, true);
        $result = curl_exec($ch);
        if ($result === false) {
            throw new \Exception(curl_error($ch));
        }
        $header=substr($result, 0, curl_getinfo($ch, CURLINFO_HEADER_SIZE));
        curl_close($ch);
        return $header;
    }
    /**
     * Save the SPO auth cookies
     * @param mixed $header
     */
    protected function saveAuthCookies($header)
    {
        $cookies = HttpUtilities::cookieParse($header);
        $this->FedAuth = $cookies['FedAuth'];
        $this->rtFa = $cookies['rtFa'];
    }
    /**
     * Request the token
     *
     * @param string $username
     * @param string $password
     * @return string
     * @throws Exception
     */
    protected function requestToken($username, $password)
    {
        $samlRequest = $this->buildSamlRequest($username, $password, $this->url);
        $ch = $this->initCurl(self::$stsUrl);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $samlRequest);
        $result = curl_exec($ch);
        if ($result === false) {
            throw new \Exception(curl_error($ch));
        }
        curl_close($ch);
        return $this->processToken($result);
    }
    /**
     * Verify and extract security token from the HTTP response
     * @param mixed $body
     * @return mixed
     */
    protected function processToken($body)
    {
      $xml = new \DOMDocument();
        $xml->loadXML($response);
        $xpath = new \DOMXPath($xml);
        if ($xpath->query("//wsse:BinarySecurityToken")->length > 0) {
            $nodeToken = $xpath->query("//wsse:BinarySecurityToken")->item(0);
            if (!empty($nodeToken)) {
              return $nodeToken->nodeValue;
            }
        }

        if ($xpath->query("//S:Fault")->length > 0) {
            // Returning the full fault value in case any other response comes within the fault node.
            throw new \RuntimeException($xpath->query("//S:Fault")->item(0)->nodeValue);
        }

        throw new \RuntimeException('Error trying to get a token, check your URL or credentials');
    }
    /**
     * Construct the XML to request the security token
     *
     * @param string $username
     * @param string $password
     * @param string $address
     * @return type string
     */
    protected function buildSamlRequest($username, $password, $address)
    {
        $samlRequestTemplate =
'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
      xmlns:a="http://www.w3.org/2005/08/addressing"
      xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <s:Header>
    <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</a:Action>
    <a:ReplyTo>
      <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
    </a:ReplyTo>
    <a:To s:mustUnderstand="1">https://login.microsoftonline.com/extSTS.srf</a:To>
    <o:Security s:mustUnderstand="1"
       xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <o:UsernameToken>
        <o:Username>{username}</o:Username>
        <o:Password>{password}</o:Password>
      </o:UsernameToken>
    </o:Security>
  </s:Header>
  <s:Body>
    <t:RequestSecurityToken xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust">
      <wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">
        <a:EndpointReference>
          <a:Address>{address}</a:Address>
        </a:EndpointReference>
      </wsp:AppliesTo>
      <t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType>
      <t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType>
      <t:TokenType>urn:oasis:names:tc:SAML:1.0:assertion</t:TokenType>
    </t:RequestSecurityToken>
  </s:Body>
</s:Envelope>';
        $samlRequestTemplate = str_replace('{username}', $username, $samlRequestTemplate);
        $samlRequestTemplate = str_replace('{password}', $password, $samlRequestTemplate);
        $samlRequestTemplate = str_replace('{address}', $address, $samlRequestTemplate);
        return $samlRequestTemplate;
    }
}
class HttpUtilities {
    /**
     * Parse cookies
     * @param mixed $header
     * @return mixed
     */
    public static function cookieParse($header)
    {
        $headerLines = explode("\r\n", $header);
        $cookies = array();
        foreach ($headerLines as $line) {
            if (preg_match('/^Set-Cookie: /i', $line)) {
                $line = preg_replace('/^Set-Cookie: /i', '', trim($line));
                $csplit = explode(';', $line);
                $cinfo = explode('=', $csplit[0], 2);
                $cookies[$cinfo[0]] = $cinfo[1];
            }
        }
        return $cookies;
    }
}
// =========================================
function connectSPO($url, $username, $password){
    try {
        $client = new SPOClient($url);
        $client->signIn($username, $password);
    } catch (Exception $e){
        echo 'Authentication failed: ',  $e->getMessage(), "\n";
    }
    return $client;
}
function getData($host, $authCookies){
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $host);
    curl_setopt($ch, CURLOPT_COOKIE, $authCookies);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    $result = curl_exec($ch);
    // Catch error
    if($result === false) {
        throw new Exception('Curl error: ' . curl_error($ch));
    }
    // Close connection
    curl_close($ch);
    return $result;
}
// =========================================
$username = 'syssp-p-nbrsffeed@dentsuaegis.com';
$password = 'Password01';
$url      = 'https://globalappsportal.sharepoint.com/sites/NBR';
$client = connectSPO($url, $username, $password);
$authCookies = 'FedAuth=' . $client->FedAuth . ';rtFa=' . $client->rtFa;
$data = getData($url, $authCookies);
