# ISSENDORFF.LCNGVS.Commands

Das PowerShell Module ISSENDORFF.LCNGVS.Commands wurde entwickelt, um über die PowerShell Kommandos an den LCN-GVS Visualisierungsserver zu senden. Es bietet u.a. die gleichen Funktionalitäten, wie die [LCN-GVS-App](https://apps.apple.com/de/app/lcn-gvs/id646477852) und verwendet ausschließlich die WebServices des LCN-GVS-Visualisierungsservers. Die LCN-GVS-App ist die Visualisierungsoberfläche für iPhone, iPad und iPod Touch für das LCN-GVS "Globale Visualisierungs-System" der ISSENDORFF KG.

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
Alias           Add-LCNGVSMonitoringAction                         1.1.0.0    ISSENDORFF.LCNGVS.Commands
Alias           Add-LCNGVSMonitoringEvent                          1.1.0.0    ISSENDORFF.LCNGVS.Commands
Alias           Add-LCNGVSTimerEvent                               1.1.0.0    ISSENDORFF.LCNGVS.Commands
Alias           Check-UserRight                                    1.1.0.0    ISSENDORFF.LCNGVS.Commands
Alias           Close-Tableau                                      1.1.0.0    ISSENDORFF.LCNGVS.Commands
Alias           Execute-Command                                    1.1.0.0    ISSENDORFF.LCNGVS.Commands
Alias           Execute-CommandAsync                               1.1.0.0    ISSENDORFF.LCNGVS.Commands
Alias           Get-Control                                        1.1.0.0    ISSENDORFF.LCNGVS.Commands
Alias           Get-Image                                          1.1.0.0    ISSENDORFF.LCNGVS.Commands
Alias           Get-LcnBusConnectionState                          1.1.0.0    ISSENDORFF.LCNGVS.Commands
Alias           Get-LCNGVSTableau                                  1.1.0.0    ISSENDORFF.LCNGVS.Commands
Alias           Get-LCNGVSTableauControl                           1.1.0.0    ISSENDORFF.LCNGVS.Commands
Alias           Get-LCNGVSTableauList                              1.1.0.0    ISSENDORFF.LCNGVS.Commands
Alias           Get-LogAccessControl                               1.1.0.0    ISSENDORFF.LCNGVS.Commands
Alias           Get-LoginResult                                    1.1.0.0    ISSENDORFF.LCNGVS.Commands
Alias           Get-LogLCNGVS                                      1.1.0.0    ISSENDORFF.LCNGVS.Commands
Alias           Get-LogLcnServer                                   1.1.0.0    ISSENDORFF.LCNGVS.Commands
Alias           Get-LogMacroServer                                 1.1.0.0    ISSENDORFF.LCNGVS.Commands
Alias           Get-LogTimer                                       1.1.0.0    ISSENDORFF.LCNGVS.Commands
Alias           Get-PluginInfo                                     1.1.0.0    ISSENDORFF.LCNGVS.Commands
Alias           Get-ServerInfo                                     1.1.0.0    ISSENDORFF.LCNGVS.Commands
Alias           Get-ServerInfoAsync                                1.1.0.0    ISSENDORFF.LCNGVS.Commands
Alias           Get-Status                                         1.1.0.0    ISSENDORFF.LCNGVS.Commands
Alias           Get-StatusAsync                                    1.1.0.0    ISSENDORFF.LCNGVS.Commands
Alias           Get-TableauControl                                 1.1.0.0    ISSENDORFF.LCNGVS.Commands
Alias           Get-Tableaus                                       1.1.0.0    ISSENDORFF.LCNGVS.Commands
Alias           Get-UserRights                                     1.1.0.0    ISSENDORFF.LCNGVS.Commands
Alias           Load-Dic                                           1.1.0.0    ISSENDORFF.LCNGVS.Commands
Alias           Load-dicAsync                                      1.1.0.0    ISSENDORFF.LCNGVS.Commands
Alias           Login-LCNGVSServer                                 1.1.0.0    ISSENDORFF.LCNGVS.Commands
Alias           Logout-LCNGVSServer                                1.1.0.0    ISSENDORFF.LCNGVS.Commands
Alias           Logout-LCNGVSServerAsync                           1.1.0.0    ISSENDORFF.LCNGVS.Commands
Alias           Open-Tableau                                       1.1.0.0    ISSENDORFF.LCNGVS.Commands
Alias           Poll-Updates                                       1.1.0.0    ISSENDORFF.LCNGVS.Commands
Alias           Save-Image                                         1.1.0.0    ISSENDORFF.LCNGVS.Commands
Alias           Submit-Button                                      1.1.0.0    ISSENDORFF.LCNGVS.Commands
Alias           Submit-Dimmer                                      1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Close-LCNGVSTableau                                1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Close-LCNGVSTrendLog                               1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Connect-LCNGVS                                     1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Copy-LCNGVSTimerEvent                              1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Disconnect-LCNGVS                                  1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Disconnect-LCNGVSAsync                             1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Export-LCNGVSImage                                 1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Export-LCNGVSTrendLog                              1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSAppSiriItem                              1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSAppSiriItemAsync                         1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSCommands                                 1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSControl                                  1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSControlUpdateList                        1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSCustomData                               1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSImage                                    1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSLastTableauUri                           1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSLogEntry                                 1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSMacro                                    1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSMacroListAsync                           1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSMacroServerEnabled                       1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSMonitoringAction                         1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSMonitoringEvent                          1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSQuickTableauUri                          1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSRecentTableauList                        1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSServerInfo                               1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSServerInfoAsync                          1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSServerLcnBusConnectionState              1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSServerPluginInfo                         1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSServerStatus                             1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSServerStatusAsync                        1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSSession                                  1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSSupportedTrendLogSources                 1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSTableauGroupInfo                         1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSTimerEvent                               1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSTrendLogs                                1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSTrendLogValues                           1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSTrendLogValuesMultiple                   1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Get-LCNGVSUserRights                               1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Invoke-LCNGVSAppSiriAbsRegulatorCommand            1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Invoke-LCNGVSAppSiriAbsRegulatorCommandAsync       1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Invoke-LCNGVSAppSiriChangeBrightnessCommand        1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Invoke-LCNGVSAppSiriChangeBrightnessCommandAsync   1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Invoke-LCNGVSAppSiriCommand                        1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Invoke-LCNGVSAppSiriCommandAsync                   1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Invoke-LCNGVSAppSiriDimmingCommand                 1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Invoke-LCNGVSAppSiriDimmingCommandAsync            1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Invoke-LCNGVSAppSiriRelRegulatorCommand            1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Invoke-LCNGVSAppSiriRelRegulatorCommandAsync       1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Invoke-LCNGVSButton                                1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Invoke-LCNGVSDimmer                                1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Invoke-LCNGVSMacro                                 1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Invoke-LCNGVSMacroAsync                            1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        New-LCNGVSCustomData                               1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        New-LCNGVSMonitoringAction                         1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        New-LCNGVSMonitoringEvent                          1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        New-LCNGVSTableauUri                               1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        New-LCNGVSTimerEvent                               1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Open-LCNGVSTableau                                 1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Open-LCNGVSTrendLog                                1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Receive-WSDLFile                                   1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Remove-LCNGVSMonitoringAction                      1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Remove-LCNGVSMonitoringEvent                       1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Remove-LCNGVSTimerEvent                            1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Set-LCNGVSCustomData                               1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Set-LCNGVSLastTableauUri                           1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Set-LCNGVSMacroServerEnabled                       1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Set-LCNGVSMonitoringAction                         1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Set-LCNGVSMonitoringEvent                          1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Set-LCNGVSTimerEvent                               1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Test-LCNGVSUserRight                               1.1.0.0    ISSENDORFF.LCNGVS.Commands
Function        Unregister-Device                                  1.1.0.0    ISSENDORFF.LCNGVS.Commands
```

## Hinweis
Dieses Modul wurde mit einem LCN-GVS-Visualisierungsserver in der Version 4.8.2 und 4.8.3 getestet.
