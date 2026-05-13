# Adminer Plugins

Custom plugins for [Adminer](https://www.adminer.org/) 5.x.

---

## Plugins

### `turnstile-captcha.php` — Cloudflare Turnstile CAPTCHA

Adds a [Cloudflare Turnstile](https://developers.cloudflare.com/turnstile/) CAPTCHA widget to the Adminer login page. The token is validated server-side before any login attempt is processed. If validation fails, the login is blocked regardless of credentials.

#### How it works

| Hook | Purpose |
|---|---|
| `loginFormField` | Injects the Turnstile widget div and script after the Database field |
| `login` | Validates the submitted `cf-turnstile-response` token against Cloudflare's siteverify API |
| `csp` | Extends Adminer's Content-Security-Policy to allow `challenges.cloudflare.com` for `script-src`, `frame-src`, and `connect-src` |

The plugin fails **closed** — if the Cloudflare API is unreachable, login is denied.

---

## Setup

### 1. Get Turnstile keys

1. Go to [Cloudflare Dashboard → Turnstile](https://dash.cloudflare.com/?to=/:account/turnstile)
2. Create a new widget
3. Add your hostname (e.g. `yourdomain.com` or `localhost` for local dev)
4. Copy the **Site Key** (public) and **Secret Key** (private)

### 2. File structure

Place the plugin file alongside `adminer-plugins.php`:

```
adminer/
├── adminer.php              ← Adminer core (single-file build)
├── adminer-plugins.php       ← Plugin loader (you create/edit this)
└── adminer-plugins/
    └── turnstile-captcha.php ← This plugin
```

### 3. Configure `adminer-plugins.php`

Create or edit `adminer-plugins.php` in the same directory as `adminer.php`:

```php
<?php // adminer-plugins.php
return array(
    new AdminerTurnstileCaptcha(
        'YOUR_SITE_KEY',    // public key from Cloudflare dashboard
        'YOUR_SECRET_KEY'   // secret key — never expose this client-side
    ),
);
```

Adminer automatically discovers this file and wraps the returned array in its plugin system.

> **Security:** Never commit your secret key to version control. Use an environment variable or a config file outside the web root.

---

## Local development

Cloudflare Turnstile requires the hostname to be registered. For `localhost`:

1. Add `localhost` to your widget's **Hostname Management** in the Cloudflare dashboard
2. Or use Cloudflare's built-in test keys that always pass:
   - Site key: `1x00000000000000000000AA`
   - Secret key: `1x0000000000000000000000000000000AA`

---

## Requirements

- Adminer **5.x** (single-file build, `adminer.php`)
- PHP **7.4+**
- `allow_url_fopen = On` in `php.ini` (needed for the server-side token verification call)
- Outbound HTTPS access from the server to `challenges.cloudflare.com`

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Widget not visible | Hostname not registered in Cloudflare | Add your hostname in the Turnstile widget settings |
| Widget not visible | CSP blocking Cloudflare | Ensure you are using Adminer 5.x — the `csp()` hook is required |
| 500 error on load | `adminer-plugins.php` returns wrong structure | The file must `return array(new AdminerTurnstileCaptcha(...))` — do not wrap in `new AdminerPlugin()` |
| Login blocked even with valid CAPTCHA | `allow_url_fopen` disabled | Enable it in `php.ini`, or replace `file_get_contents` with a cURL call |
| Login form fields missing | Plugin's `loginFormField` returning non-null for all fields | Only the `db` field hook should return a modified string; all others return `null` |

---

## License

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)
