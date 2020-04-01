# ISSENDORFF.LCNGVS.Commands/Invoke-LCNGVSButton
Dieser Befehl führt die Funktion eines Button auf einem Tableau aus.

## Parameter

| Parameter Name   | Beschreibung                                                  | Mandatory? |
| ---------------- | ------------------------------------------------------------ | ---------- |
| tableauSessionId        | Gibt die SessionId des Tableaus an, auf dem der Button zu finden ist. | Yes        |
| controllId       | Gibt die controllId des auszuführenden Buttons an. | Yes        |

## Verwendung

```PowerShell
# Laden Sie das Module in die PowerShell
PS > Import-Module ISSENDORFF.LCNGVS.Commands

# Verbinden Sie die PowerShell mit dem LCN-GVS-Visualisierungsserver
PS > Connect-LcnGvs -Uri "http://localhost/lcngvs" -Credential (Get-Credential)

# Das Tableau aufrufen
PS > $Tableau = Get-LCNGVSTableau -tableauGroupName Haus -tableauId Wohnzimmer

# Alle Buttons des Tableaus anzeigen
PS > $Tableau.Controls | Where-Object -Property type -EQ -Value Button

# Button ausführen
PS > Invoke-LCNGVSButton -tableauSessionId $Tableau.tableauSessionId -controllId 212
```

## Hinweis
Dieses Modul befindet sich in der Entwicklung und wurde mit einem LCN-GVS-Visualisierungsserver 4.8.2 getestet.