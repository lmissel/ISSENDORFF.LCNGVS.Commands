# ISSENDORFF.LCNGVS.Commands/Invoke-LCNGVSSiriCommand
Dieser Befehl führt ein LCN-Siri-Sprachbefehl aus. 

Um diese Funktion nutzen zu können, müssen Sie unter der Sprachsteuerung des LCN-GVS-Visualisierungsserver die Sprachbefehle hinterlegen. Die Webservices bieten leider keine Funktionen hierzu an.

## Parameter

| Parameter Name   | Beschreibung                                                  | Mandatory? |
| ---------------- | ------------------------------------------------------------- | ---------- |
| listSpeechIntent | Gibt den Namen des Sprachbefehls an.                          | Yes        |
| itemTitle        | Gibt den Namen des spezifischen Sprachbefehls an.             | Yes        |

## Verwendung

```PowerShell
# Laden Sie das Module in die PowerShell
PS > Import-Module ISSENDORFF.LCNGVS.Commands

# Verbinden Sie die PowerShell mit dem LCN-GVS-Visualisierungsserver
PS > Connect-LcnGvs -Uri "http://localhost/lcngvs" -Credential (Get-Credential)

# Rufen Sie, wenn nötig, alle vorhandenen LCN-Siri-Sprachbefehle ab.
PS > Get-LCNGVSSiriData -all

# Führen Sie den gewünschten LCN-Siri-Sprachbefehl aus.
PS > Invoke-LCNGVSSiriCommand -listSpeechIntent 'Wohnzimmer' -itemTitle 'Licht'
```

## Hinweis
Dieses Modul befindet sich in der Entwicklung und wurde mit einem LCN-GVS-Visualisierungsserver 4.8.2 getestet.