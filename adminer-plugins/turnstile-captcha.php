<?php
/**
 * Cloudflare Turnstile CAPTCHA plugin for Adminer login page.
 *
 * Renders the Turnstile widget on the login form and validates the token
 * server-side before allowing access. Login is blocked if validation fails.
 *
 * Setup:
 *   1. Get your Site Key and Secret Key from https://dash.cloudflare.com/?to=/:account/turnstile
 *   2. Pass them when registering the plugin (see adminer-plugins.php example below).
 *
 * Usage in adminer-plugins.php:
 *   <?php
 *   return array(
 *       new AdminerTurnstileCaptcha('YOUR_SITE_KEY', 'YOUR_SECRET_KEY'),
 *   );
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

        // Validate the token during the login POST and store the result in the
        // session here in the constructor — same pattern as AdminerLoginOtp.
        // session_regenerate_id() preserves existing session data, so values
        // written here survive into the session that login() reads later.
        if (!empty($_POST['auth'])) {
            $token = isset($_POST['cf-turnstile-response']) ? trim($_POST['cf-turnstile-response']) : '';

            if ($token !== '' && $this->verifyToken($token)) {
                $_SESSION['turnstile_passed'] = true;
                $_SESSION['turnstile_error']  = null;
            } else {
                $_SESSION['turnstile_passed'] = false;
                $_SESSION['turnstile_error']  = ($token === '')
                    ? 'Please complete the CAPTCHA before logging in.'
                    : 'CAPTCHA verification failed. Please try again.';
            }
        }
    }

    /**
     * Extend Adminer's Content-Security-Policy to allow Turnstile's iframe and API calls.
     *
     * @param array $csp Existing CSP directives (array of directive-map arrays)
     * @return array Modified CSP directives
     */
    public function csp(array $csp) {
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
     * Block login if the CAPTCHA was not solved.
     * Reads the flag stored in the constructor — same request lifecycle as
     * AdminerLoginOtp's OTP check.
     *
     * @param string $login    Submitted username
     * @param string $password Submitted password
     * @return bool|null null = allow, false/string = block
     */
    public function login($login, $password) {
        if (isset($_SESSION['turnstile_passed'])) {
            $passed = $_SESSION['turnstile_passed'];
            unset($_SESSION['turnstile_passed']);

            if (!$passed) {
                return false;
            }
        }

        return null;
    }

    /**
     * Inject the Turnstile widget and display any CAPTCHA error message.
     *
     * @param string $name  Field name being rendered
     * @param string $label HTML label cell
     * @param string $input HTML input element
     * @return string|null Modified field HTML, or null to leave unchanged
     */
    public function loginFormField($name, $label, $input) {
        $siteKey   = htmlspecialchars($this->siteKey,   ENT_QUOTES, 'UTF-8');
        $scriptUrl = htmlspecialchars($this->scriptUrl, ENT_QUOTES, 'UTF-8');

        // Prepend any CAPTCHA error above the first field
        if ($name === 'driver') {
            $error = '';
            if (!empty($_SESSION['turnstile_error'])) {
                $error = '<tr><td colspan="2"><div class="error" style="margin-bottom:0.5em;">'
                       . htmlspecialchars($_SESSION['turnstile_error'], ENT_QUOTES, 'UTF-8')
                       . '</div></td></tr>' . "\n";
                unset($_SESSION['turnstile_error']);
            }
            return $error . $label . $input . "\n";
        }

        // After the last field (db), close the table, render the widget, reopen table.
        // Scripts cannot be direct children of <table>, so we break out of it.
        // script_src() carries Adminer's CSP nonce so the script is allowed.
        if ($name === 'db') {
            $widget  = $label . $input . "\n";
            $widget .= '</table>' . "\n";
            $widget .= \Adminer\script_src($scriptUrl, true);
            $widget .= '<div class="cf-turnstile" data-sitekey="' . $siteKey . '" style="margin: 0.5em 0;"></div>' . "\n";
            $widget .= '<table>' . "\n";
            return $widget;
        }

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
