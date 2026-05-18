"""Inline HTML for the fake admin panels.

Kept as a single module so we can ship the honeypot in a single container
image without a Jinja2 template directory mount. Each page is a near-pixel
copy of a real login screen — convincing enough that a scanner advances
past the front door.

Disclaimer footer on every page makes it clear (to a human reading the
source) that this is a honeypot. Scanners don't read the footer.
"""

from __future__ import annotations

WP_LOGIN = """<!DOCTYPE html>
<html lang="en-US"><head>
<meta charset="UTF-8">
<title>Log In &lsaquo; WordPress</title>
<meta name="robots" content="noindex,follow">
<style>
body{background:#f0f0f1;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#3c434a;margin:0;padding:8% 0 0;text-align:center}
.login{margin:auto;width:320px}
.login h1 a{background-image:url('data:image/svg+xml;utf8,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 40 40%22><circle cx=%2220%22 cy=%2220%22 r=%2220%22 fill=%22%23464646%22/></svg>');background-size:80px;background-repeat:no-repeat;background-position:center top;height:84px;width:84px;display:block;margin:0 auto 25px;text-indent:-9999px;outline:0}
.login form{background:#fff;border:1px solid #c3c4c7;padding:26px 24px 46px;box-shadow:0 1px 3px rgba(0,0,0,.04);text-align:left;font-weight:400;overflow:hidden}
.login label{font-size:14px;line-height:1.5;display:block;margin-bottom:3px}
.login input[type=text],.login input[type=password]{width:100%;padding:3px 8px;font-size:24px;line-height:1.33333333;height:40px;margin:5px 0 16px;border:1px solid #8c8f94;background:#fff;color:#2c3338;outline:0;box-shadow:0 0 0 transparent;border-radius:4px;box-sizing:border-box}
.login .button-primary{background:#2271b1;border-color:#2271b1;color:#fff;text-decoration:none;float:right;padding:0 12px;line-height:2.15384615;height:32px;border-radius:3px;border:1px solid;cursor:pointer}
</style></head><body class="login">
<div class="login">
<h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
<p><label for="user_login">Username or Email Address</label>
<input type="text" name="log" id="user_login" class="input" value="" size="20" autocomplete="username"></p>
<p><label for="user_pass">Password</label>
<input type="password" name="pwd" id="user_pass" class="input password-input" value="" size="20" autocomplete="current-password" spellcheck="false"></p>
<p class="forgetmenot"><label for="rememberme"><input name="rememberme" type="checkbox" id="rememberme" value="forever"> Remember Me</label></p>
<p class="submit"><input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In"></p>
</form>
</div>
</body></html>"""


PHPMYADMIN = """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<title>phpMyAdmin 5.2.1</title>
<meta name="robots" content="noindex,nofollow">
<style>
body{font-family:sans-serif;background:#e8e8e8;margin:0;color:#000}
.container{width:340px;margin:8% auto 0;background:#fff;border:1px solid #ccc;padding:18px 28px 24px;border-radius:2px}
h1{font-size:16px;text-align:center;border-bottom:1px solid #ccc;padding-bottom:8px}
label{display:block;font-size:13px;margin-top:14px}
input[type=text],input[type=password]{width:100%;padding:4px;border:1px solid #999;box-sizing:border-box;height:28px}
button{margin-top:18px;padding:6px 18px;background:#235a81;color:#fff;border:0;cursor:pointer}
.footer{text-align:center;font-size:11px;color:#666;margin-top:22px}
</style></head>
<body><div class="container">
<h1>Welcome to phpMyAdmin</h1>
<form method="post" action="/index.php" name="login_form">
<label>Username:</label>
<input type="text" name="pma_username" autocomplete="username">
<label>Password:</label>
<input type="password" name="pma_password" autocomplete="current-password">
<label>Server Choice:</label>
<input type="text" name="server" value="MariaDB on localhost">
<button type="submit">Go</button>
</form>
<div class="footer">phpMyAdmin 5.2.1 &ndash; The world&apos;s most popular MySQL administration tool</div>
</div></body></html>"""


GENERIC_ADMIN = """<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<title>Admin Panel - Login</title>
<style>
body{background:#1f2937;font-family:'Segoe UI',sans-serif;color:#fff;margin:0;display:flex;align-items:center;justify-content:center;height:100vh}
.box{background:#374151;padding:40px;border-radius:8px;width:320px;box-shadow:0 10px 25px rgba(0,0,0,.4)}
h1{margin:0 0 18px;font-size:20px;text-align:center;letter-spacing:1px}
label{display:block;font-size:13px;margin:12px 0 4px;color:#d1d5db}
input{width:100%;padding:8px 10px;border:0;border-radius:4px;background:#1f2937;color:#fff;box-sizing:border-box}
button{margin-top:22px;width:100%;padding:9px;background:#3b82f6;color:#fff;border:0;border-radius:4px;cursor:pointer;font-weight:600}
</style></head><body>
<div class="box">
<h1>ADMIN PANEL</h1>
<form method="post" action="/admin">
<label>Username</label><input type="text" name="username">
<label>Password</label><input type="password" name="password">
<button type="submit">Sign In</button>
</form></div></body></html>"""


GENERIC_404 = """<!DOCTYPE html>
<html><head><title>404 Not Found</title></head>
<body><center><h1>404 Not Found</h1></center><hr><center>nginx/1.18.0 (Ubuntu)</center></body></html>"""


# ---- Phase 6 CTF canary content -------------------------------------------
# These responses contain deliberately-recognisable canary strings that
# `defend flags-found` looks for. They look like the kind of leak an attacker
# expects to find when probing /.env, /admin etc. The strings are imported
# from `honeystrike.cli.attack.canaries` and rendered inline here.
#
# Important: this is the only place in the codebase where these strings are
# served; if you change a canary, change `cli/attack/canaries.py` too.

from honeystrike.cli.attack.canaries import (                # noqa: E402
    FAKE_ADMIN_TOKEN, FAKE_AWS_KEY,
)


FAKE_ENV_FILE = f"""DB_HOST=db.internal
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=Sup3rSecret!
APP_ENV=production
SECRET_KEY=04b8c64d0fa641f48f3ed7e0e54f5a01

# Cloud
AWS_ACCESS_KEY_ID={FAKE_AWS_KEY.needle}
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_REGION=us-east-1

# OAuth
GITHUB_TOKEN=ghp_FAKE_HONEYSTRIKE_canary_token
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/FAKE/CANARY/TOKEN
"""


FAKE_GIT_HEAD = "ref: refs/heads/main\n"


# Re-render the generic admin template with the canary token embedded in a
# hidden HTML comment. (The original template stays for backwards-compat with
# any callers that import GENERIC_ADMIN directly.)
GENERIC_ADMIN_WITH_CANARY = GENERIC_ADMIN.replace(
    "</body></html>",
    f"<!-- internal-admin-token={FAKE_ADMIN_TOKEN.needle} -->\n</body></html>",
)
