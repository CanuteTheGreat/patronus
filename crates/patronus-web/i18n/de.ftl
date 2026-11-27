# Patronus Weboberfläche und API-Meldungen: Deutsch (Fluent-Syntax). Schlüssel und Variablen
# entsprechen en.ftl; ci/check-i18n.py prüft das.

lang-name = Deutsch

## Seitenleiste
nav-section-overview = Übersicht
nav-section-security = Sicherheit
nav-section-network = Netzwerk
nav-section-services = Dienste
nav-section-advanced = Erweitert
nav-dashboard = Dashboard
nav-firewall = Firewall
nav-vpn = VPN
nav-wifi = WLAN
nav-interfaces = Schnittstellen
nav-routing = Routing
nav-dhcp = DHCP
nav-dns = DNS
nav-ntp = NTP
nav-ha = Hochverfügbarkeit
nav-qos = Bandbreitenverwaltung
nav-segmentation = Gerätesegmentierung
nav-guest = Gastnetzwerk
nav-syslog = Syslog
nav-netflow = NetFlow-Export
nav-igmp = IGMP-Proxy
nav-mdns = mDNS-Repeater
nav-udp-relay = UDP-Broadcast-Relay
nav-nat64 = NAT64 / DNS64
nav-l2tp = L2TP-Server
nav-ids = Angriffserkennung
nav-frr = BGP / OSPF
nav-wol = Wake-on-LAN
nav-monitoring = Überwachung
nav-insights = Datenverkehr-Analyse
nav-time-limits = Zeitlimits
nav-dns-policy = DNS-Richtlinie & Protokolle
nav-diagnostics = Diagnose
nav-packages = Pakete
nav-device = Gerät
nav-system = System
brand-tagline = Firewall
status-online = System online
about-this-patronus = Über dieses Patronus
menu-open = Menü öffnen
js-nav-unavailable-hint = Auf diesem Gerät nicht verfügbar: öffnen Sie den Eintrag, um den Grund zu sehen
js-nav-unavailable-suffix = (nicht verfügbar)

## Kopfzeile
crumb-home = Start
crumb-dhcp = DHCP
crumb-dns = DNS
crumb-dns-policy = DNS-Richtlinie
crumb-ntp = NTP
crumb-qos = Bandbreitenverwaltung
crumb-vpn = VPN
crumb-wifi = WLAN
crumb-ha = Hochverfügbarkeit
crumb-time-limits = Zeitlimits
crumb-firewall = Firewall
crumb-interfaces = Schnittstellen
crumb-routing = Routing
crumb-network = Netzwerk
crumb-monitoring = Überwachung
crumb-insights = Datenverkehr-Analyse
crumb-diagnostics = Diagnose
crumb-packages = Pakete
crumb-system = System
crumb-device = Gerät
crumb-segmentation = Gerätesegmentierung
crumb-api-docs = API-Referenz
header-search = Suchen...
theme-toggle = Dunkelmodus umschalten
setup-banner-text = Dieser Router wurde noch nicht eingerichtet.
setup-banner-link = Einrichtungsassistenten starten

## Anmeldeseite
login-title = Anmelden
login-subtitle = Firewall-Verwaltung
login-username = Benutzername
login-password = Passwort
login-totp = Zwei-Faktor-Code (Authenticator-App oder Wiederherstellungscode)
login-submit = Anmelden
login-language = Sprache

## Spracheinstellungen (Seite System)
lang-card-title = Sprache
lang-card-intro = Die Sprache dieser Weboberfläche und der Meldungen, die die API zurückgibt. Zuerst gilt Ihre eigene Auswahl, dann die Systemvorgabe, dann die Sprache, die Ihr Browser anfordert.
lang-my = Ihre Sprache
lang-use-system = Systemvorgabe verwenden
lang-system = Systemvorgabe für die Sprache
lang-follow-browser = Dem Browser folgen
lang-save = Speichern
lang-system-admin-only = Nur Administratoren können die Systemvorgabe ändern.

## Seite API-Referenz
apidocs-title = API-Referenz
apidocs-intro = Alles, was diese Oberfläche tut, läuft über diese API. Melden Sie sich mit der Browser-Sitzung an oder senden Sie einen API-Schlüssel als Authorization: Bearer oder X-API-Key.
apidocs-download = openapi.json herunterladen
apidocs-search = Pfade und Beschreibungen durchsuchen
apidocs-count = Operationen
apidocs-no-match = Keine Treffer.
apidocs-loading = API-Beschreibung wird geladen...
apidocs-failed = Die API-Beschreibung konnte nicht geladen werden.
apidocs-parameters = Parameter
apidocs-request-body = Anfragekörper
apidocs-responses = Antworten
apidocs-no-auth = Keine Anmeldung nötig
apidocs-people-only = Für API-Schlüssel nicht verfügbar
apidocs-required = erforderlich

## Texte der Seitenskripte
js-not-applied = Nicht angewendet:
js-advanced-open = Erweitert ▼
js-advanced-close = Erweitert ▲
js-theme-to-light = Zum hellen Modus wechseln
js-theme-to-dark = Zum dunklen Modus wechseln
js-login-network-error = Netzwerkfehler: Der Router hat nicht geantwortet. Bitte versuchen Sie es erneut.
js-login-cookie-stuck = Das Passwort wurde akzeptiert, aber dieser Browser hat die Anmeldung nicht an den Router zurückgesendet. Möglicherweise stehen Daten einer älteren Firmware für diese Adresse im Weg: Löschen Sie Cookies und Websitedaten für diese Adresse im Browser und melden Sie sich erneut an.
js-login-failed = Anmeldung fehlgeschlagen (HTTP {"{$status}"})

## API-Meldungen (der englische Text ist der Schlüssel; $v1.. sind die variablen Teile)
err-first-run-required = Ersteinrichtung erforderlich: Legen Sie das Administratorkonto unter /first-run an
err-invalid-api-key = Ungültiger oder abgelaufener API-Schlüssel
err-not-for-api-keys = Für API-Schlüssel nicht verfügbar
err-read-only-key = Schreibgeschützter API-Schlüssel
err-read-only-account = Schreibgeschütztes Konto
err-auth-required = Anmeldung erforderlich
err-first-run-exists = Ein Administratorkonto existiert bereits
err-password-mismatch = Ungültiges Passwort: Die beiden Eingaben unterscheiden sich
err-no-api-key = Kein solcher API-Schlüssel
err-no-account = Kein solches Konto
err-no-session = Keine Sitzung gefunden
err-session-expired = Ungültige oder abgelaufene Sitzung
err-bad-credentials = Ungültiger Benutzername oder ungültiges Passwort
err-account-disabled = Das Benutzerkonto ist deaktiviert
err-no-permission = Unzureichende Berechtigungen
err-internal = Interner Fehler
err-totp-required = Zwei-Faktor-Code erforderlich
err-totp-invalid = Ungültiger Zwei-Faktor-Code
err-totp-invalid-clock = Ungültiger Zwei-Faktor-Code (prüfen Sie die Uhr des Telefons)
err-totp-not-built = Die Zwei-Faktor-Authentifizierung ist in dieses Patronus nicht eingebaut (mit USE=totp neu bauen)
err-totp-not-built-account = Dieses Konto verwendet die Zwei-Faktor-Anmeldung, aber dieses Patronus wurde ohne TOTP (USE=totp) gebaut. Bauen Sie es damit neu oder schalten Sie 2FA des Kontos am Gerät mit `patronus users reset-2fa <name>` ab.
err-throttle-account = Zu viele fehlgeschlagene Anmeldeversuche für dieses Konto; versuchen Sie es in { $v1 } erneut.
err-throttle-address = Zu viele fehlgeschlagene Anmeldeversuche von dieser Adresse; versuchen Sie es in { $v1 } erneut.
err-system-account = Dies ist ein Systemkonto: Ändern Sie sein Passwort auf dem System (passwd), nicht hier
err-2fa-already-on = Ungültige Anfrage: Die Zwei-Faktor-Anmeldung ist bereits eingeschaltet (zuerst ausschalten)
err-2fa-not-on = Ungültige Anfrage: Die Zwei-Faktor-Anmeldung ist nicht eingeschaltet
err-2fa-start-first = Ungültige Anfrage: Starten Sie zuerst die Zwei-Faktor-Einrichtung
err-2fa-restarted = Ungültige Anfrage: Die Zwei-Faktor-Einrichtung wurde bereits bestätigt oder neu gestartet (Seite neu laden und prüfen)
err-user-exists = Ungültiger Benutzername: { $v1 } existiert bereits
err-last-admin = Ungültige Änderung: Mindestens ein aktives Administratorkonto muss bestehen bleiben
err-password-default = Ungültiges Passwort ist eine öffentlich bekannte Voreinstellung
err-password-short = Ungültiges Passwort muss mindestens { $v1 } Zeichen lang sein
err-bad-role = Ungültige Rolle { $v1 }: admin, operator oder readonly
err-bad-username = Ungültiger Benutzername { $v1 }: 1-32 Buchstaben, Ziffern, '.', '_' oder '-'
err-bad-language = Ungültige Sprache '{ $v1 }': Dafür gibt es keinen Katalog
err-bad-language-tag = Ungültige Sprache '{ $v1 }': Verwenden Sie ein Sprachkürzel wie en oder de, oder auto
err-key-no-language = API-Schlüssel haben keine eigene Sprache: Stellen Sie sie am Konto ein

## Zeitspannen in Meldungen
wait-seconds =
    { $n ->
        [one] { $n } Sekunde
       *[other] { $n } Sekunden
    }
wait-minutes =
    { $n ->
        [one] { $n } Minute
       *[other] { $n } Minuten
    }

nav-reverse-proxy = Reverse-Proxy
hw-title = Hardware-Einstellungen
hw-intro = Einstellungen, die das Image dieses Geräts für seine Hardware wählt, mit dem Grund für jeden Standardwert.
hw-col-setting = Einstellung
hw-col-value = Wert
hw-col-why = Grund
hw-col-change = Ändern
