# ISSENDORFF.LCNGVS.Commands/Invoke-LCNGVSMacro
Dieser Befehl führt ein Macro aus.

## Parameter

| Parameter Name   | Beschreibung                                                  | Mandatory? |
| ---------------- | ------------------------------------------------------------- | ---------- |
| macroName        | Gibt den Namen des auszuführenden Macros an.                  | Yes        |

## Verwendung

```PowerShell
# Laden Sie das Module in die PowerShell
PS > Import-Module ISSENDORFF.LCNGVS.Commands

# Verbinden Sie die PowerShell mit dem LCN-GVS-Visualisierungsserver
PS > Connect-LcnGvs -Uri "http://localhost/lcngvs" -Credential (Get-Credential)

# Rufen Sie, wenn nötig, alle vorhandenen Makros ab.
PS > Get-LCNGVSMacro -all

# Führen Sie das gewünschte Makro aus.
PS > Invoke-LCNGVSMacro -macroName 'Toggle Gartenbeleuchtung'
```

## Hinweis
Dieses Modul befindet sich in der Entwicklung und wurde mit einem LCN-GVS-Visualisierungsserver 4.8.2 getestet.