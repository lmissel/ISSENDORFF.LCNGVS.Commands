# ISSENDORFF.LCNGVS.Commands/Connect-LCNGVS
## Alias: Login-LCNGVSServer

Mit diesem Befehl melden Sie sich am LCN-GVS Server an.

## Parameter

| Parameter Name   | Beschreibung                                                  | Mandatory? |
| ---------------- | ------------------------------------------------------------ | ---------- |
| Uri        | Gibt die Url des LCN-GVS Serversan . | Yes        |
| Credential       | Gibt die Credential (Benutzername und Password) an. | Yes        |
| CreatePersistentCookie       | Gibt an, ob der Cookie persistent erstellt werden soll. | No        |

## Verwendung

```PowerShell
# Laden Sie das Module in die PowerShell
PS > Import-Module ISSENDORFF.LCNGVS.Commands

# Verbinden Sie die PowerShell mit dem LCN-GVS-Visualisierungsserver
PS > Connect-LcnGvs -Uri "http://localhost/lcngvs" -Credential (Get-Credential)
```

## Hinweis
Dieses Modul befindet sich in der Entwicklung und wurde mit einem LCN-GVS-Visualisierungsserver 4.8.2 getestet.