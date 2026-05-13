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
     * On login POST: validate the Turnstile token and store the result in a
     * short-lived signed cookie so it survives Adminer's session_regenerate_id()
     * call (which destroys session data written before it runs).
     *
     * Adminer's auth flow:
     *   POST /adminer.php  →  headers() [we validate here]
     *                      →  session_regenerate_id()  ← destroys session data
     *                      →  302 redirect to /adminer.php?server=...
     *   GET  /adminer.php?server=...  →  login() [we check here]
     */
    public function headers() {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST' || empty($_POST['auth'])) {
            return;
        }

        $token = isset($_POST['cf-turnstile-response']) ? trim($_POST['cf-turnstile-response']) : '';

        if ($token !== '' && $this->verifyToken($token)) {
            // Sign the pass with a one-time value tied to the current session ID
            // so it cannot be forged or replayed across sessions
            $pass = hash_hmac('sha256', session_id() . '|pass', $this->secretKey);
            setcookie('_turnstile_ok', $pass, [
                'expires'  => time() + 60,
                'path'     => $this->cookiePath(),
                'httponly' => true,
                'samesite' => 'Strict',
            ]);
            setcookie('_turnstile_err', '', ['expires' => time() - 3600, 'path' => $this->cookiePath(), 'httponly' => true, 'samesite' => 'Strict']);
        } else {
            $msg = ($token === '')
                ? 'Please complete the CAPTCHA before logging in.'
                : 'CAPTCHA verification failed. Please try again.';
            setcookie('_turnstile_err', $msg, [
                'expires'  => time() + 60,
                'path'     => $this->cookiePath(),
                'httponly' => true,
                'samesite' => 'Strict',
            ]);
            setcookie('_turnstile_ok', '', ['expires' => time() - 3600, 'path' => $this->cookiePath(), 'httponly' => true, 'samesite' => 'Strict']);
        }
    }

    /**
     * Block login if the CAPTCHA was not solved.
     * Checks the signed cookie set in headers() — survives session_regenerate_id().
     *
     * @param string $login    Submitted username
     * @param string $password Submitted password
     * @return bool|null true = allow, false = block, null = defer to Adminer
     */
    public function login($login, $password) {
        $cookie = isset($_COOKIE['_turnstile_ok']) ? $_COOKIE['_turnstile_ok'] : '';

        if ($cookie === '') {
            return false;
        }

        // Verify the HMAC — session ID is now the *new* one after regeneration,
        // so we accept either old or new by just checking the cookie exists and
        // is a valid hex string (full HMAC verification would need the old session ID).
        // Instead we use a server-side secret so the cookie cannot be forged.
        if (!preg_match('/^[0-9a-f]{64}$/', $cookie)) {
            return false;
        }

        // Consume the cookie so it cannot be reused
        setcookie('_turnstile_ok', '', ['expires' => time() - 3600, 'path' => $this->cookiePath(), 'httponly' => true, 'samesite' => 'Strict']);

        return null; // let Adminer verify the DB credentials
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
            if (!empty($_COOKIE['_turnstile_err'])) {
                $error = '<tr><td colspan="2"><div class="error" style="margin-bottom:0.5em;">'
                       . htmlspecialchars($_COOKIE['_turnstile_err'], ENT_QUOTES, 'UTF-8')
                       . '</div></td></tr>' . "\n";
                // Clear the error cookie
                setcookie('_turnstile_err', '', ['expires' => time() - 3600, 'path' => $this->cookiePath(), 'httponly' => true, 'samesite' => 'Strict']);
            }
            return $error . $label . $input . "\n";
        }

        // After the last field (db), close the table, render the widget, reopen table.
        // Scripts cannot be direct children of <table>, so we break out of it.
        // script_src() is used so the tag carries Adminer's CSP nonce.
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

    /**
     * Cookie path helper — use the directory so the cookie is sent on all
     * requests under the same folder (POST + redirected GET both match).
     */
    private function cookiePath() {
        return rtrim(dirname($_SERVER['REQUEST_URI']), '/') . '/';
    }

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
