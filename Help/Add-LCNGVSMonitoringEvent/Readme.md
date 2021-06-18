# ISSENDORFF.LCNGVS.Commands/Set-LCNGVSMonitoringEvent
## Alias: Add-LCNGVSMonitoringEvent

Das LCN-GVS verfuegt ueber einen Ereignismelder, der Zustaende im LCN-Bus ueberwacht und beim Eintreten von vordefinierten Ereignissen entsprechende Aktionen ausfuehrt. Mit diesem Befehl koennen Sie den uebergebenen im LCN-GVS eingerichteten Ereignismelder aendern oder fuegen einen neuen hinzu.

ANMERKUNG:
Fuer den Ereignismelder sind Lizenzen erforderlich (entsprechend der Anzahl eingerichteter Ereignisse).

## Parameter

| Parameter Name   | Beschreibung                                                  | Mandatory? |
| ---------------- | ------------------------------------------------------------ | ---------- |
| Event        | Das MonitoringEvent, welches hinzugefuegt oder geaendert werden soll. | Yes        |

## Verwendung

```PowerShell
# Laden Sie das Module in die PowerShell
PS > Import-Module ISSENDORFF.LCNGVS.Commands

# Verbinden Sie die PowerShell mit dem LCN-GVS-Visualisierungsserver
PS > Connect-LcnGvs -Uri "http://localhost/lcngvs" -Credential (Get-Credential)

# Hinzufuegen eines neuen MonitoringEvents
PS > Add-LCNGVSMonitoringEvent -Event $Event
```

## Hinweis
Dieses Modul befindet sich in der Entwicklung und wurde mit einem LCN-GVS-Visualisierungsserver 4.8.2 getestet.