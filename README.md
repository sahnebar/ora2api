# GWM ORA 03 API Telemetrie-Abruf für Home Assistant (Python)

Dieses Repository enthält ein Python-Skript, um den aktuellen Fahrzeugstatus (Batterieladestand/SOC, Reichweite, Kilometerstand und Ladestatus) eines **GWM ORA 03** (ehemals Ora Funky Cat) über die offizielle europäische GWM H5/App-Gateway-API auszulesen und direkt als JSON für Home Assistant zur Verfügung zu stellen.

> [!NOTE]
> Dieses Python-Skript ersetzt die archivierte C#-Implementierung (`ora2mqtt`), da es robuster läuft, keine externen OpenSSL-Konfigurationsdateien benötigt und sich nahtlos in die Command-Line-Sensoren von Home Assistant integrieren lässt.

---

## Features
* **Programmatischer OpenSSL 3 Workaround**: Löst das Problem `[SSL: CA_MD_TOO_WEAK]` (durch die schwachen Signaturen der GWM-Zertifikate unter modernen Betriebssystemen wie Alpine Linux 3.23.3) vollautomatisch direkt im Python-Prozess. **Es wird keine `openssl.cnf` oder Umgebungsvariablen wie `OPENSSL_CONF` mehr benötigt!**
* **Automatischer Token-Refresh**: Das Skript speichert den Anmeldetoken lokal in einer JSON-Datei ab. Ist dieser abgelaufen (nach 24 Stunden), wird er im Hintergrund mithilfe des Refresh-Tokens geräuschlos erneuert.
* **Automatischer 2FA / Mail-Abruf**: Wenn GWM beim Anmelden ein neues Gerät erkennt und einen 4-stelligen Verifizierungscode per E-Mail sendet, kann das Skript diesen über ein konfigurierbares E-Mail-Postfach (z. B. Gmail IMAP mit App-Passwort) selbstständig auslesen und die Anmeldung abschließen.
* **Formatierte JSON-Ausgabe**: Bereitstellung aller relevanten Zustandsdaten in einem standardisierten JSON-Format, das perfekt von Home Assistant eingelesen und verarbeitet werden kann.

---

## Voraussetzungen

### 1. Python-Bibliotheken
Das Skript benötigt `requests` und `cryptography`. Installiere diese auf deinem System (z. B. über das Home Assistant Terminal):
```bash
pip install requests cryptography
```
*(Bei Alpine Linux/Home Assistant OS kann dies je nach Paketverwaltung auch über `apk add py3-requests py3-cryptography` oder in einer virtuellen Umgebung durchgeführt werden.)*

### 2. GWM-Account & E-Mail (Gmail empfohlen)
Da GWM-Bestätigungs-E-Mails von Outlook/Microsoft oft stumm gelöscht werden, wird die Verwendung einer Gmail-Adresse für den GWM-Account empfohlen.
Für die automatische 2FA-Anmeldung:
* Aktiviere **IMAP** in deinem Gmail-Konto.
* Erstelle ein **App-Passwort** (2-Faktor-Authentifizierung in Google-Sicherheitseinstellungen -> App-Passwörter).

---

## Installation & Einrichtung

1. Erstelle einen Ordner in deinem Home Assistant `/config/`-Verzeichnis, z. B. `/config/gwm/`.
2. Kopiere die Datei `gwm_ora_status.py` in diesen Ordner.
3. Kopiere die Datei `gwm_config.json.example` in den Ordner und benenne sie in `gwm_config.json` um.
4. Trage in der `gwm_config.json` deine Zugangsdaten ein:

```json
{
  "country": "DE",
  "username": "DEINE_GWM_EMAIL@gmail.com",
  "password": "DEIN_GWM_PASSWORT",
  "deviceId": "3b6d697c75834a598495ced54640dfd9",
  "accessToken": "",
  "refreshToken": "",
  "imap": {
    "server": "imap.gmail.com",
    "user": "DEINE_GWM_EMAIL@gmail.com",
    "password": "DEIN_GMAIL_APP_PASSWORT"
  }
}
```

> [!TIP]
> Die `deviceId` kann ein beliebiger 32-stelliger Hex-String sein (z.B. per Online-Generator). Ist dieser einmal festgelegt, erkennt GWM das Skript dauerhaft als "bekanntes/vertrauenswürdiges Gerät", wodurch nach der ersten erfolgreichen Anmeldung keine 2FA-E-Mails mehr nötig sind.

### Initialer Login (Interaktiv)
Führe das Skript beim ersten Mal interaktiv im Terminal aus, um die Erstanmeldung und die Geräteverifizierung durchzuführen:
```bash
python3 /config/gwm/gwm_ora_status.py
```
Das Skript loggt sich ein, holt ggf. den Verifizierungscode aus deinem Postfach, speichert die aktiven Session-Tokens in der `gwm_config.json` ab und gibt deine Fahrzeugdaten im Terminal aus.

---

## Home Assistant Integration

Das Skript wird über einen **Command Line Sensor** in Home Assistant eingebunden, welcher das JSON-Ausgabeformat ausliest.

### 1. Command Line Sensor
Trage Folgendes in deine `configuration.yaml` ein (bzw. in deine `sensors.yaml`, falls du deine Konfiguration aufgeteilt hast):

```yaml
command_line:
  - sensor:
      name: GWM ORA 03 Status
      unique_id: gwm_ora_03_status
      command: "python3 /config/gwm/gwm_ora_status.py --json"
      value_template: "{{ value_json.soc }}"
      unit_of_measurement: "%"
      device_class: battery
      scan_interval: 600  # Abfrage alle 10 Minuten (schont den Fahrzeugakku & verhindert API-Sperren)
      json_attributes:
        - vin
        - series_name
        - range
        - odometer
        - charging_status
        - charging_active
        - charging_plugged
```

### 2. Einzelne Template-Sensoren
Um die einzelnen Werte als eigenständige Entitäten in deinem Dashboard und für Automationen nutzen zu können, erstelle folgende Template-Sensoren in deiner `configuration.yaml`:

```yaml
template:
  - sensor:
      - name: "ORA SOC"
        unique_id: ora_soc
        state: "{{ states('sensor.gwm_ora_03_status') }}"
        unit_of_measurement: "%"
        device_class: battery
        
      - name: "ORA Reichweite"
        unique_id: ora_range
        state: "{{ state_attr('sensor.gwm_ora_03_status', 'range') }}"
        unit_of_measurement: "km"
        device_class: distance
        
      - name: "ORA Kilometerstand"
        unique_id: ora_odometer
        state: "{{ state_attr('sensor.gwm_ora_03_status', 'odometer') }}"
        unit_of_measurement: "km"
        device_class: distance
        state_class: total_increasing
        
      - name: "ORA Ladestatus"
        unique_id: ora_charging_status
        state: "{{ state_attr('sensor.gwm_ora_03_status', 'charging_status') }}"
```

### 3. Neustart / Laden der Entitäten
Nachdem du die YAML-Dateien angepasst hast:
1. Gehe in Home Assistant zu **Entwicklerwerkzeuge** -> **YAML**.
2. Klicke auf **Befehlszeilen-Entitäten neu laden** und **Template-Entitäten neu laden** (oder starte Home Assistant neu).
3. Die Entitäten befüllen sich innerhalb weniger Sekunden mit den echten Werten deines Fahrzeugs.

---

## Funktionsweise der SSL-Absenkung (Technischer Hintergrund)
Das GWM-Gateway nutzt ein mTLS-Client-Zertifikat, das von einer CA mit einer veralteten MD5- oder SHA1-Signatur ausgestellt wurde. Neuere OpenSSL-Versionen (wie sie z. B. in Alpine Linux v3.23.3 standardmäßig eingesetzt werden) blockieren solche Verbindungen streng mit der Meldung `[SSL: CA_MD_TOO_WEAK]`.

Dieses Skript löst das Problem zur Laufzeit im Python-Prozess:
1. Es bindet die Funktion `OSSL_PROVIDER_load` aus der Systembibliothek `libcrypto.so` via `ctypes` ein.
2. Es lädt die OpenSSL-Provider `default` und `legacy` in den aktuellen Prozesskontext.
3. Es klinkt sich global in den `init_poolmanager` von Pythons `urllib3`/`requests` ein und senkt das TLS-Sicherheitsniveau explizit auf `SECLEVEL=0` ab (`DEFAULT@SECLEVEL=0`).

Dies ermöglicht eine sichere verschlüsselte HTTPS-Verbindung zu GWM unter Umgehung der strikten OpenSSL-Signaturprüfung – ohne globale Betriebssystemänderungen vornehmen zu müssen.
