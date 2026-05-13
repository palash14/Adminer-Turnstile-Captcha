<?php
/**
 * Cloudflare Turnstile CAPTCHA plugin for Adminer login page.
 *
 * Renders the Turnstile widget on the login form and validates the token
 * server-side before allowing access. Login is blocked if validation fails.
 *
 * Setup:
 *   1. Get your Site Key and Secret Key from https://dash.cloudflare.com/?to=/:account/turnstile
 *   2. Pass them when registering the plugin (see index.php example below).
 *
 * Usage in index.php:
 *   function adminer_object() {
 *       include_once './plugins/plugin.php';
 *       foreach (glob('./plugins/*.php') as $filename) { include_once $filename; }
 *       $plugins = [
 *           new AdminerTurnstileCaptcha('YOUR_SITE_KEY', 'YOUR_SECRET_KEY'),
 *       ];
 *       return new AdminerPlugin($plugins);
 *   }
 *
 * @link https://www.adminer.org/plugins/#use
 * @link https://developers.cloudflare.com/turnstile/
 * @license https://www.apache.org/licenses/LICENSE-2.0 Apache License, Version 2.0
 */
class AdminerTurnstileCaptcha {

    /** @var string Cloudflare Turnstile site key (public) */
    private $siteKey;

    /** @var string Cloudflare Turnstile secret key (private, server-side only) */
    private $secretKey;

    /** @var string Turnstile JS script URL */
    private $scriptUrl = 'https://challenges.cloudflare.com/turnstile/v0/api.js';

    /** @var string Turnstile server-side verification endpoint */
    private $verifyUrl = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

    /**
     * @param string $siteKey   Your Turnstile site key
     * @param string $secretKey Your Turnstile secret key
     */
    public function __construct($siteKey, $secretKey) {
        $this->siteKey   = $siteKey;
        $this->secretKey = $secretKey;
    }

    /**
     * Extend Adminer's Content-Security-Policy to allow Turnstile's iframe and API calls.
     * Turnstile renders a challenge inside an iframe from challenges.cloudflare.com
     * and makes XHR calls to the same origin.
     *
     * @param array $csp Existing CSP directives (array of directive-map arrays)
     * @return array Modified CSP directives
     */
    public function csp(array $csp) {
        // $csp is an array of directive-map arrays. Walk each group and extend
        // frame-src / connect-src / script-src to include Cloudflare Turnstile.
        foreach ($csp as &$group) {
            if (isset($group['frame-src'])) {
                $group['frame-src'] .= ' https://challenges.cloudflare.com';
            }
            if (isset($group['connect-src'])) {
                $group['connect-src'] .= ' https://challenges.cloudflare.com';
            }
            if (isset($group['script-src'])) {
                $group['script-src'] .= ' https://challenges.cloudflare.com';
            }
        }
        unset($group);
        return $csp;
    }

    /**
     * Inject the Turnstile widget into the login form.
     * Adminer calls loginFormField for each field; we hook 'password' to append
     * the widget right after the password row, inside the form table.
     *
     * @param string $name  Field name being rendered
     * @param string $label HTML label cell
     * @param string $input HTML input element
     * @return string|null  Modified field HTML, or null to leave unchanged
     */
    public function loginFormField($name, $label, $input) {
        if ($name !== 'db') {
            return null;
        }

        $siteKey   = htmlspecialchars($this->siteKey,   ENT_QUOTES, 'UTF-8');
        $scriptUrl = htmlspecialchars($this->scriptUrl, ENT_QUOTES, 'UTF-8');

        // db row (unchanged)
        $widget  = $label . $input . "\n";
        // Close the table, inject widget outside it (scripts can't live inside <table>),
        // then reopen an empty <table> so Adminer's closing </table> still matches.
        // Use script_src() so the nonce is included and Adminer's CSP allows the script.
        $widget .= '</table>' . "\n";
        $widget .= \Adminer\script_src($scriptUrl, true);  // true = defer
        $widget .= '<div class="cf-turnstile" data-sitekey="' . $siteKey . '" style="margin: 0.5em 0;"></div>' . "\n";
        $widget .= '<table>' . "\n";

        return $widget;
    }

    /**
     * Validate the Turnstile token before allowing login.
     * Adminer calls this hook with the submitted username and password.
     * Returning false blocks the login attempt.
     *
     * @param string $login    Submitted username
     * @param string $password Submitted password
     * @return bool|null  null = let Adminer decide; false = block login
     */
    public function login($login, $password) {
        // Only run validation on POST (i.e. an actual login submission)
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            return null;
        }

        $token = isset($_POST['cf-turnstile-response']) ? trim($_POST['cf-turnstile-response']) : '';

        if ($token === '') {
            // No token submitted — block login and show an error
            $this->showError('Please complete the CAPTCHA before logging in.');
            return false;
        }

        if (!$this->verifyToken($token)) {
            $this->showError('CAPTCHA verification failed. Please try again.');
            return false;
        }

        // Token is valid — let Adminer proceed with credential checking
        return null;
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Call the Turnstile siteverify API and return whether the token is valid.
     *
     * @param string $token The cf-turnstile-response value from the form
     * @return bool
     */
    private function verifyToken($token) {
        $payload = http_build_query([
            'secret'   => $this->secretKey,
            'response' => $token,
            'remoteip' => $this->getClientIp(),
        ]);

        $context = stream_context_create([
            'http' => [
                'method'  => 'POST',
                'header'  => "Content-Type: application/x-www-form-urlencoded\r\n"
                           . "Content-Length: " . strlen($payload) . "\r\n",
                'content' => $payload,
                'timeout' => 10,
            ],
        ]);

        $response = @file_get_contents($this->verifyUrl, false, $context);

        if ($response === false) {
            // Network error — fail closed (deny login) to be safe
            return false;
        }

        $data = json_decode($response, true);

        return isset($data['success']) && $data['success'] === true;
    }

    /**
     * Render an inline error message above the login form.
     * Uses Adminer's existing error styling class.
     *
     * @param string $message Human-readable error text
     */
    private function showError($message) {
        echo '<div class="error" style="margin-bottom:0.5em;">'
           . htmlspecialchars($message, ENT_QUOTES, 'UTF-8')
           . '</div>' . "\n";
    }

    /**
     * Return the real client IP, respecting common proxy headers.
     *
     * @return string
     */
    private function getClientIp() {
        foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'] as $key) {
            if (!empty($_SERVER[$key])) {
                // X-Forwarded-For can be a comma-separated list; take the first entry
                return trim(explode(',', $_SERVER[$key])[0]);
            }
        }
        return '';
    }
}
