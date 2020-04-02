# ISSENDORFF.LCNGVS.Commands

Das PowerShell Module ISSENDORFF.LCNGVS.Commands wurde entwickelt, um über die PowerShell Kommandos an den LCN-GVS Visualisierungsserver zu senden. Es bietet die gleichen Funktionalitäten, wie die [LCN-GVS-App](https://apps.apple.com/de/app/lcn-gvs/id646477852) und verwendet ausschließlich die WebServices des LCN-GVS-Visualisierungsservers. Die LCN-GVS-App ist die Visualisierungsoberfläche für iPhone, iPad und iPod Touch für das LCN-GVS "Globale Visualisierungs-System" der ISSENDORFF KG.

[Weitere Informationen zu LCN](https://www.lcn.eu/)

## Wie kam es zu diesem Modul?
Vorweg, ich bin begeistert von der Technik die LCN entwickelt und weiß auch den LCN-GVS-Visualisierungsserver zu schätzen. Dennoch fehlen mir ein paar Funktionen, vorallem bei der Anbindung von Drittanbietern. Mein Ziel ist es, mehrere PowerShell Module und Webservices bereitzustellen mit denen man den LCN-GVS-Visualisierungsserver steuern, verwalten oder mit Drittanbietern erweitern kann. Aus diesem Grund kam es zu diesem Modul. Anfangen wollte ich mit den vorhandenen Schnittstellen, wie hier den Webservices, um schonmal die Grundfunktionalitäten bereitzustellen.

## Wie kann ich das Modul verwenden?

Kopieren Sie das Module in eins der vorgesehenden PowerShell-Module-Pfade. Importieren Sie anschließend das Module in die aktive PowerShell Instance, verbinden Sie die PowerShell mit dem Server und starten Sie z.B. mit dem Abrufen aller verfügbaren Cmdlets.

```PowerShell
# Laden Sie das Module
PS lmissel> Import-Module ISSENDORFF.LCNGVS.Commands

# Verbinden mit dem Server
PS lmissel> Connect-LcnGvs -Uri "http://localhost/lcngvs" -Credential (Get-Credential)

# Abrufen aller Cmdlets
PS lmissel> Get-Command -Module ISSENDORFF.LCNGVS.Commands

CommandType     Name                                               Version    Source                                
-----------     ----                                               -------    ------                                
Function        Connect-LCNGVS                                     0.0        ISSENDORFF.LCNGVS.Commands
Function        Disconnect-LCNGVS                                  0.0        ISSENDORFF.LCNGVS.Commands
Function        Export-LCNGVSTrendLog                              0.0        ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSCommands                                 0.0        ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSControlUpdates                           0.0        ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSCustomData                               0.0        ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSImage                                    0.0        ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSLastTableauUri                           0.0        ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSLogEntry                                 0.0        ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSMacro                                    0.0        ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSMacroServerEnabled                       0.0        ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSMonitoringEvent                          0.0        ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSRecentTableauList                        0.0        ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSServerInfo                               0.0        ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSServerStatus                             0.0        ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSSiriData                                 0.0        ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSSupportedTrendLogSource                  0.0        ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSTableau                                  0.0        ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSTableauGroupInfo                         0.0        ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSTrendLog                                 0.0        ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSUserRights                               0.0        ISSENDORFF.LCNGVS.Commands
Function        Invoke-LCNGVSButton                                0.0        ISSENDORFF.LCNGVS.Commands
Function        Invoke-LCNGVSDimmer                                0.0        ISSENDORFF.LCNGVS.Commands
Function        Invoke-LCNGVSMacro                                 0.0        ISSENDORFF.LCNGVS.Commands
Function        Invoke-LCNGVSAppSiriCommand                        0.0        ISSENDORFF.LCNGVS.Commands
Function        New-LCNGVSCustomData                               0.0        ISSENDORFF.LCNGVS.Commands
Function        New-LCNGVSMonitoringEvent                          0.0        ISSENDORFF.LCNGVS.Commands
Function        Remove-LCNGVSMonitoringEvent                       0.0        ISSENDORFF.LCNGVS.Commands
Function        Set-LCNGVSCustomData                               0.0        ISSENDORFF.LCNGVS.Commands
Function        Set-LCNGVSMacroServerEnabled                       0.0        ISSENDORFF.LCNGVS.Commands
Function        Set-LCNGVSMonitoringEvent                          0.0        ISSENDORFF.LCNGVS.Commands
Function        Start-LCNGVSTrendLog                               0.0        ISSENDORFF.LCNGVS.Commands
Function        Stop-LCNGVSTrendLog                                0.0        ISSENDORFF.LCNGVS.Commands
...
```

## Hinweis
Dieses Modul befindet sich in der Entwicklung und wurde mit einem LCN-GVS-Visualisierungsserver 4.8.2 getestet.
