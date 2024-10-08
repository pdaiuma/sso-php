<?php
namespace ADR28\SSO\PHP\Services;

use Exception;

class SSOService
{

    protected $config;
    private $state;
    private $logFile;

    public function __construct() {

        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $this->config = require __DIR__ . '/../config/config.php';
        $this->logFile = __DIR__ . '/../log/sso_log.txt';

        if (!isset($_SESSION['_sso_state'])) {
            $this->state = bin2hex(random_bytes(16));
            $_SESSION['_sso_state'] = $this->state;
        } else {
            $this->state = $_SESSION['_sso_state'];
        }
    }

    private function log($message, $type = 'INFO') {
        $time = date('Y-m-d H:i:s');
        $logMessage = "[$time] [$type]: $message" . PHP_EOL;
        file_put_contents($this->logFile, $logMessage, FILE_APPEND);
    }

    public function getKeycloakConfig() {
        return $this->config['keycloak'];
    }

    public function getBaseUrl() {
        return $this->getKeycloakConfig()['base_url'];
    }

    public function getState() {
        return $this->state;
    }

    public function getOpenIDConfig()
    {
        $config = $this->getKeycloakConfig();
        $baseUrl = $config['base_url'];
        return [
            'issuer' => $baseUrl . '/' . $config['realm'],
            'authorization_endpoint' => $baseUrl . '/protocol/openid-connect/auth',
            'token_endpoint' => $baseUrl . '/protocol/openid-connect/token',
            'userinfo_endpoint' => $baseUrl . '/protocol/openid-connect/userinfo',
            'end_session_endpoint' => $baseUrl . '/protocol/openid-connect/logout',
            'jwks_uri' => $baseUrl . '/protocol/openid-connect/certs',
        ];
    }

    public function getLoginUrl() {
        try {
            $config = $this->getKeycloakConfig();
            $loginUrl = $this->getBaseUrl() . '/realms/' . $config['realm'] . '/protocol/openid-connect/auth?' . http_build_query([
                'client_id' => $config['client_id'],
                'redirect_uri' => $config['callback'],
                'response_type' => 'code',
                'scope' => 'openid',
                'state' => $this->getState(),
            ]);

            $this->log("Login URL generated: $loginUrl");
            return $loginUrl;

        } catch (Exception $e) {
            $this->log("Failed to generate login URL: " . $e->getMessage(), 'ERROR');
            throw $e;
        }
    }

    public function authenticate($code) {
        try {
            $config = $this->getKeycloakConfig();
            $tokenUrl = $this->getBaseUrl() . '/realms/' . $config['realm'] . '/protocol/openid-connect/token';
            $postData = [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'client_id' => $config['client_id'],
                'client_secret' => $config['client_secret'],
                'redirect_uri' => $config['callback'],
            ];

            $response = $this->httpPost($tokenUrl, $postData);
            if (isset($response['access_token'])) {
                $_SESSION['access_token'] = $response['access_token'];
                $_SESSION['refresh_token'] = $response['refresh_token'];
                $this->log("Authentication successful for code: $code");
                return true;
            }
            $this->log("Authentication failed for code: $code", 'ERROR');
            return false;

        } catch (Exception $e) {
            $this->log("Exception during authentication: " . $e->getMessage(), 'ERROR');
            throw $e;
        }
    }

    public function logout() {
        session_start();
        session_destroy();

        $config = $this->getKeycloakConfig();
        $logoutUrl = $this->getBaseUrl() . '/realms/' . $config['realm'] . '/protocol/openid-connect/logout?' . http_build_query([
            'client_id' => $config['client_id'],
            'redirect_uri' => $config['redirect_url'],
        ]);
        
        header("Location: $logoutUrl");
        exit();
    }

    public function introspectToken($token) {
        $config = $this->getKeycloakConfig();
        $introspectionUrl = $this->getBaseUrl() . '/realms/' . $config['realm'] . '/protocol/openid-connect/token/introspect';

        $response = $this->httpPost($introspectionUrl, [
            'token' => $token,
            'client_id' => $config['client_id'],
            'client_secret' => $config['client_secret'],
        ]);

        return isset($response['active']) && $response['active'];
    }

    public function getAccessToken() {
        return $_SESSION['access_token'] ?? null;
    }

    public function isAuthenticated() {
        return $this->getAccessToken() && $this->introspectToken($this->getAccessToken());
    }

    public function direct() {
        if (isset($_GET['state']) && isset($_GET['code'])) {
            $state = $_GET['state'];
            $code = $_GET['code'];

            try {
                if (!$this->validateState($state)) {
                    $this->log("Invalid state parameter");
                    throw new \Exception('Invalid state parameter.');
                    return;
                }

                $tokens = $this->authenticate($code);
                if ($tokens) {
                    $userInfo = $this->getUserProfile($this->getAccessToken());
                    if ($userInfo) {
                        $_SESSION['name'] = $userInfo['name'];
                        $_SESSION['username'] = $userInfo['preferred_username'];

                        header("Location: index.php?page=index");
                        exit;
                    } else {
                        $this->log("Failed to retrieve user profile information.");
                        throw new \Exception('Failed to retrieve user profile information.');
                        return;
                    }

                } else {
                    $this->log("Failed to retrieve the token from the SSO callback.");
                    throw new \Exception('Failed to retrieve the token from the SSO callback.');
                    return;
                }

            } catch (\Exception $e) {
                $this->log('SSO Error in callback: ' . $e->getMessage());
                echo 'Login failed, please try again.';
            }
        } else {
            $this->log('Missing state or code parameter');
            header("Location: index.php?page=index");
        }
    }


    public function validateState($state) {
        $challenge = $this->getState();
        return (!empty($state) && !empty($challenge) && $challenge === $state);
    }

    public function getUserProfile($accessToken) {
        $userinfoUrl = $this->getBaseUrl() . '/realms/' . $this->getKeycloakConfig()['realm'] . '/protocol/openid-connect/userinfo';

        $response = $this->httpGet($userinfoUrl, $accessToken);
        
        if (isset($response['error'])) {
            $this->log('Error fetching user profile: ' . $response['error']);
            return null; 
        }
        return $response;
    }


    protected function httpGet($url, $accessToken) {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Authorization: Bearer ' . $accessToken 
        ]);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);

        $response = curl_exec($ch);

        if (curl_errno($ch)) {
            $errorMsg = curl_error($ch);
            curl_close($ch);
            $this->log("cURL error: $errorMsg");
            throw new \Exception("cURL error: $errorMsg");
        }

        curl_close($ch);
        return json_decode($response, true);
    }


    protected function httpPost($url, $data) {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);

        $response = curl_exec($ch);

        if (curl_errno($ch)) {
            $errorMsg = curl_error($ch);
            curl_close($ch);
            $this->log("cURL error: $errorMsg");
            throw new \Exception("cURL error: $errorMsg");
        }

        curl_close($ch);
        return json_decode($response, true);
    }

}

