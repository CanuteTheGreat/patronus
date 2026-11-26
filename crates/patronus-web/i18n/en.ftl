# Patronus web UI and API messages: English, the source catalog (Fluent syntax).
#
# * `nav-*`, `crumb-*`, `login-*`, ...: text of the pages (templates use `{{ "key"|t }}`).
# * `js-*`: strings the page scripts read from window.PATRONUS_I18N.
# * `err-*`: API error messages. The English text IS the lookup key at run time: a handler that
#   still writes the English message is translated on the way out, with $v1..$v9 standing for
#   the variable parts. New code calls i18n::api_error with a key instead.
# A new language = a new file named after its tag (de.ftl) with the same keys, plus one line in
# CATALOGS (src/i18n.rs). ci/check-i18n.py fails when a catalog lacks a key or changes a variable.

lang-name = English

## Sidebar sections and entries
nav-section-overview = Overview
nav-section-security = Security
nav-section-network = Network
nav-section-services = Services
nav-section-advanced = Advanced
nav-dashboard = Dashboard
nav-firewall = Firewall
nav-vpn = VPN
nav-wifi = Wi-Fi
nav-interfaces = Interfaces
nav-routing = Routing
nav-dhcp = DHCP
nav-dns = DNS
nav-ntp = NTP
nav-ha = High availability
nav-qos = Traffic shaping
nav-segmentation = Device segmentation
nav-guest = Guest network
nav-syslog = Syslog
nav-netflow = NetFlow export
nav-igmp = IGMP proxy
nav-mdns = mDNS repeater
nav-udp-relay = UDP broadcast relay
nav-nat64 = NAT64 / DNS64
nav-l2tp = L2TP server
nav-ids = Intrusion detection
nav-frr = BGP / OSPF
nav-wol = Wake-on-LAN
nav-monitoring = Monitoring
nav-insights = Traffic insights
nav-time-limits = Time limits
nav-dns-policy = DNS policy & logs
nav-diagnostics = Diagnostics
nav-packages = Packages
nav-device = Device
nav-system = System
brand-tagline = Firewall
status-online = System Online
about-this-patronus = About this Patronus
menu-open = Open menu
js-nav-unavailable-hint = Not available on this unit: open it to see why
js-nav-unavailable-suffix = (unavailable)

## Header
crumb-home = Home
crumb-dhcp = DHCP
crumb-dns = DNS
crumb-dns-policy = DNS policy
crumb-ntp = NTP
crumb-qos = QoS
crumb-vpn = VPN
crumb-wifi = Wi-Fi
crumb-ha = High availability
crumb-time-limits = Time limits
crumb-firewall = Firewall
crumb-interfaces = Interfaces
crumb-routing = Routing
crumb-network = Network
crumb-monitoring = Monitoring
crumb-insights = Traffic insights
crumb-diagnostics = Diagnostics
crumb-packages = Packages
crumb-system = System
crumb-device = Device
crumb-segmentation = Device segmentation
crumb-api-docs = API reference
header-search = Search...
theme-toggle = Toggle dark mode
setup-banner-text = This router has not been set up yet.
setup-banner-link = Run the setup wizard

## Sign-in page
login-title = Sign in
login-subtitle = Firewall Management System
login-username = Username
login-password = Password
login-totp = Two-factor code (authenticator app, or a recovery code)
login-submit = Sign In
login-language = Language

## Language settings (System page)
lang-card-title = Language
lang-card-intro = The language of this web interface and of the messages the API returns. Your own choice comes first, then the system default, then the language your browser asks for.
lang-my = Your language
lang-use-system = Use the system default
lang-system = System default language
lang-follow-browser = Follow the browser
lang-save = Save
lang-system-admin-only = Only administrators can change the system default.

## API reference page
apidocs-title = API reference
apidocs-intro = Everything this interface does goes through this API. Sign in with the browser session, or send an API key as Authorization: Bearer or X-API-Key.
apidocs-download = Download openapi.json
apidocs-search = Search paths and descriptions
apidocs-count = operations
apidocs-no-match = Nothing matches.
apidocs-loading = Loading the API description...
apidocs-failed = The API description could not be loaded.
apidocs-parameters = Parameters
apidocs-request-body = Request body
apidocs-responses = Responses
apidocs-no-auth = No sign-in needed
apidocs-people-only = Not available to API keys
apidocs-required = required

## Strings used by page scripts
js-not-applied = Not applied:
js-advanced-open = Advanced ▼
js-advanced-close = Advanced ▲
js-theme-to-light = Switch to light mode
js-theme-to-dark = Switch to dark mode
js-login-network-error = Network error: the router did not answer. Please try again.
js-login-cookie-stuck = The password was accepted, but this browser did not send the sign-in back to the router. Data stored for this address by an older firmware may be in the way: clear the cookies and site data for this address in the browser, then sign in again.
js-login-failed = Sign-in failed (HTTP {"{$status}"})

## API messages (the English text is the key; $v1.. are the variable parts)
err-first-run-required = first-run setup required: create the administrator account at /first-run
err-invalid-api-key = invalid or expired API key
err-not-for-api-keys = not available to API keys
err-read-only-key = read-only API key
err-read-only-account = read-only account
err-auth-required = authentication required
err-first-run-exists = an administrator account already exists
err-password-mismatch = Invalid password: the two entries differ
err-no-api-key = no such API key
err-no-account = no such account
err-no-session = No session found
err-session-expired = Invalid or expired session
err-bad-credentials = Invalid username or password
err-account-disabled = User account is disabled
err-no-permission = Insufficient permissions
err-internal = Internal error
err-totp-required = Two-factor code required
err-totp-invalid = Invalid two-factor code
err-totp-invalid-clock = Invalid two-factor code (check the phone's clock)
err-totp-not-built = two-factor authentication is not built into this Patronus (rebuild with USE=totp)
err-totp-not-built-account = This account uses two-factor login, but this Patronus is built without TOTP (USE=totp). Rebuild with it, or turn the account's 2FA off on the box with `patronus users reset-2fa <name>`.
err-throttle-account = Too many failed sign-in attempts for this account; try again in { $v1 }.
err-throttle-address = Too many failed sign-in attempts from this address; try again in { $v1 }.
err-system-account = This is a system account: change its password on the system (passwd), not here
err-2fa-already-on = Invalid request: two-factor login is already on (disable it first)
err-2fa-not-on = Invalid request: two-factor login is not on
err-2fa-start-first = Invalid request: start the two-factor setup first
err-2fa-restarted = Invalid request: the two-factor setup was already confirmed or restarted (reload and check)
err-user-exists = Invalid username: { $v1 } already exists
err-last-admin = Invalid change: at least one enabled admin account must remain
err-password-default = Invalid password is a publicly known default
err-password-short = Invalid password must be at least { $v1 } characters
err-bad-role = Invalid role { $v1 }: admin, operator or readonly
err-bad-username = Invalid username { $v1 }: 1-32 letters, digits, '.', '_' or '-'
err-bad-language = Invalid language '{ $v1 }': no catalog for it
err-bad-language-tag = Invalid language '{ $v1 }': use a language tag such as en or de, or auto
err-key-no-language = API keys have no language of their own: set it on the account instead

## Time spans in messages
wait-seconds =
    { $n ->
        [one] { $n } second
       *[other] { $n } seconds
    }
wait-minutes =
    { $n ->
        [one] { $n } minute
       *[other] { $n } minutes
    }
