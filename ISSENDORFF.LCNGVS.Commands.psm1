###############################################################
#
# PowerShell Module: ISSENDORFF.LCNGVS.Commands
#
# Das PowerShell Module ISSENDORFF.LCNGVS.Commands wurde entwickelt, um ueber die PowerShell 
# Kommandos an den LCN-GVS Visualisierungssserver zu senden. Es bietet die gleichen Funktionalitaeten, wie 
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
$Global:LCNGVSSession = $null
$Global:LCNGVS_Dictionary = Import-LocalizedData

# -----------------------------------------------
# Private Funktionen und vieles mehr
# -----------------------------------------------
#region Helper

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
    $webrequest.CookieContainer = $Global:authSvc.CookieContainer
    $webrequest.Method = [Microsoft.PowerShell.Commands.WebRequestMethod]::Get
    $response = $webrequest.GetResponse()
    $responseStream = $response.GetResponseStream()
    $streamReader = New-Object System.IO.Streamreader($responseStream)
    $output = $streamReader.ReadToEnd()
    return $output
}

# Wird fuer Asyncrone Funktionen benoetigt...
function New-ScriptBlockCallback 
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param(
        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [scriptblock]$Callback
    )

    # Is this type already defined?
    if (-not ( 'CallbackEventBridge' -as [type]))
    {
        Add-Type @' 
            using System; 
 
            public sealed class CallbackEventBridge { 
                public event AsyncCallback CallbackComplete = delegate { }; 
 
                private CallbackEventBridge() {} 
 
                private void CallbackInternal(IAsyncResult result) { 
                    CallbackComplete(result); 
                } 
 
                public AsyncCallback Callback { 
                    get { return new AsyncCallback(CallbackInternal); } 
                } 
 
                public static CallbackEventBridge Create() { 
                    return new CallbackEventBridge(); 
                } 
            } 
'@
    }
    $bridge = [callbackeventbridge]::create()
    Register-ObjectEvent -InputObject $bridge -EventName callbackcomplete -Action $Callback -MessageData $args > $null
    $bridge.Callback
}

# Liefert alle Cmdlets des Modules
function Get-LCNGVSCommands
{
    Get-Command -Name *LCNGVS*
}

#endregion

# -----------------------------------------------
# Webservice: Authentification
# -----------------------------------------------
#region WebService: Authentification

# -----------------------------------------------
# Benutzeran- bzw. Benutzerabmeldung, Benutzerrechte
# -----------------------------------------------

# Alias: 'Login-LCNGVSServer'
function Connect-LCNGVS
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
        # Zuruecksetzen der SessionVariable
        $Global:LCNGVSSession = $null

        # Laden von Assemblys aus dem globalen Assemblycache (veraltete Methode)
        [void][System.Reflection.Assembly]::LoadWithPartialName("System.Exception")

        # Bricht die Ausfuehrung ab, wenn ein Fehler auftritt
        $ErrorActionPreference = "Stop"
    }
    Process
    {
        try
        {
            # WebService Authentification1
            [Uri] $UriAuthentification1 = $Uri.AbsoluteUri + "/WebServices/Authentification1.asmx?wsdl" # Uri erstellen
            $Global:authSvc = New-WebServiceProxy -Uri $UriAuthentification1 -Namespace "LCNGVS.Authentification" # WebProxy erstellen
            $Global:authSvc.CookieContainer = New-Object System.Net.CookieContainer # Cookies zwischenspeichern
            $Global:LCNGVSSession = $Global:authSvc.Login($Credential.UserName, $Credential.GetNetworkCredential().Password, $CreatePersistentCookie) # Anmeldung

            # EventHandler erzeugen
            Register-ObjectEvent -InputObject $Global:authSvc -EventName "LoginCompleted" -Action {
                (New-Event -SourceIdentifier "LoginCompleted" -Sender $args[0] -EventArguments $args[1])
            } | Out-Null

            Register-ObjectEvent -InputObject $Global:authSvc -EventName "LoginSecureBeginCompleted" -Action {
                (New-Event -SourceIdentifier "LoginSecureBeginCompleted" -Sender $args[0] -EventArguments $args[1])
            } | Out-Null

            Register-ObjectEvent -InputObject $Global:authSvc -EventName "LoginSecureEndCompleted" -Action {
                (New-Event -SourceIdentifier "LoginSecureEndCompleted" -Sender $args[0] -EventArguments $args[1])
            } | Out-Null
            
            Register-ObjectEvent -InputObject $Global:authSvc -EventName "LogoutCompleted" -Action {
                (New-Event -SourceIdentifier "LogoutCompleted" -Sender $args[0] -EventArguments $args[1])
            } | Out-Null
            
            Register-ObjectEvent -InputObject $Global:authSvc -EventName "GetServerInfoCompleted" -Action {
                (New-Event -SourceIdentifier "GetServerInfoCompleted" -Sender $args[0] -EventArguments $args[1])
            } | Out-Null

            Register-ObjectEvent -InputObject $Global:authSvc -EventName "SetUserCustomDataCompleted" -Action {
                (New-Event -SourceIdentifier "SetUserCustomDataCompleted" -Sender $args[0] -EventArguments $args[1])
            } | Out-Null

            if ($Global:LCNGVSSession.isSuccess)
            { 
                #region Logs1
                # WSDL herunterladen...
                [Uri] $UriLogs1 = $Uri.AbsoluteUri + "/WebServices/Logs1.asmx?wsdl"
                $output = Receive-WSDLFile -Uri $UriLogs1
                $output | Set-Content -Path "$env:TEMP\Logs1.wsdl"
                $Global:Logs1Svc = New-WebServiceProxy -Uri "$env:TEMP\Logs1.wsdl" -Namespace "LCNGVS.Logs"
                $Global:Logs1Svc.CookieContainer = $Global:authSvc.CookieContainer
                
                # EventHandler erzeugen
                Register-ObjectEvent -InputObject $Global:Logs1Svc -EventName "GetLogLcnGvsCompleted" -Action {
                    (New-Event -SourceIdentifier "GetLogLcnGvsCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:Logs1Svc -EventName "GetLogLcnServerCompleted" -Action {
                    (New-Event -SourceIdentifier "GetLogLcnServerCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:Logs1Svc -EventName "GetLogAccessControlCompleted" -Action {
                    (New-Event -SourceIdentifier "GetLogAccessControlCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:Logs1Svc -EventName "GetLogMonitoringServerCompleted" -Action {
                    (New-Event -SourceIdentifier "GetLogMonitoringServerCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null
                
                Register-ObjectEvent -InputObject $Global:Logs1Svc -EventName "GetLogTimerCompleted" -Action {
                    (New-Event -SourceIdentifier "GetLogTimerCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null
                
                Register-ObjectEvent -InputObject $Global:Logs1Svc -EventName "GetLogMacroServerCompleted" -Action {
                    (New-Event -SourceIdentifier "GetLogMacroServerCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                #endregion

                #region Status1
                # WSDL herunterladen...
                [Uri] $UriStatus1 = $Uri.AbsoluteUri + "/WebServices/Status1.asmx?wsdl"
                $output = Receive-WSDLFile -Uri $UriStatus1
                $output | Set-Content -Path "$env:TEMP\Status1.wsdl"
                $Global:Status1Svc = New-WebServiceProxy -Uri "$env:TEMP\Status1.wsdl" -Namespace "LCNGVS.Status"
                $Global:Status1Svc.CookieContainer = $Global:authSvc.CookieContainer

                # EventHandler erzeugen
                Register-ObjectEvent -InputObject $Global:Status1Svc -EventName "GetStatusCompleted" -Action {
                    (New-Event -SourceIdentifier "GetStatusCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                #endregion

                #region MacroServer1
                # WSDL herunterladen...
                [Uri] $UriMacroServer1 = $Uri.AbsoluteUri + "/WebServices/MacroServer1.asmx?wsdl"
                $output = Receive-WSDLFile -Uri $UriMacroServer1
                $output | Set-Content -Path "$env:TEMP\MacroServer1.wsdl"
                $Global:MacroServer1Svc = New-WebServiceProxy -Uri "$env:TEMP\MacroServer1.wsdl" -Namespace "LCNGVS.MacroServer"
                $Global:MacroServer1Svc.CookieContainer = $Global:authSvc.CookieContainer

                # EventHandler erzeugen
                Register-ObjectEvent -InputObject $Global:MacroServer1Svc -EventName "IsEnabledCompleted" -Action {
                    (New-Event -SourceIdentifier "IsEnabledCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:MacroServer1Svc -EventName "SetEnabledCompleted" -Action {
                    (New-Event -SourceIdentifier "SetEnabledCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null
                
                Register-ObjectEvent -InputObject $Global:MacroServer1Svc -EventName "GetMacrosCompleted" -Action {
                    (New-Event -SourceIdentifier "GetMacrosCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null
                
                Register-ObjectEvent -InputObject $Global:MacroServer1Svc -EventName "ExecuteMacroCompleted" -Action {
                    (New-Event -SourceIdentifier "ExecuteMacroCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                #endregion

                #region MonitoringServer1
                # WSDL herunterladen...
                [Uri] $UriMonitoringServer1 = $Uri.AbsoluteUri + "/WebServices/MonitoringServer1.asmx?wsdl"
                $output = Receive-WSDLFile -Uri $UriMonitoringServer1
                $output | Set-Content -Path "$env:TEMP\MonitoringServer1.wsdl"
                $Global:MonitoringServer1Svc = New-WebServiceProxy -Uri "$env:TEMP\MonitoringServer1.wsdl" -Namespace "LCNGVS.MonitoringServer"
                $Global:MonitoringServer1Svc.CookieContainer = $Global:authSvc.CookieContainer

                # EventHandler erzeugen
                Register-ObjectEvent -InputObject $Global:MonitoringServer1Svc -EventName "IsEnabledCompleted" -Action {
                    (New-Event -SourceIdentifier "IsEnabledCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:MonitoringServer1Svc -EventName "SetEnabledCompleted" -Action {
                    (New-Event -SourceIdentifier "SetEnabledCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null
                
                Register-ObjectEvent -InputObject $Global:MonitoringServer1Svc -EventName "RegisterOrReplaceDeviceCompleted" -Action {
                    (New-Event -SourceIdentifier "RegisterOrReplaceDeviceCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null
                
                Register-ObjectEvent -InputObject $Global:MonitoringServer1Svc -EventName "DeregisterDeviceCompleted" -Action {
                    (New-Event -SourceIdentifier "DeregisterDeviceCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:MonitoringServer1Svc -EventName "GetRegisteredDeviceCompleted" -Action {
                    (New-Event -SourceIdentifier "GetRegisteredDeviceCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:MonitoringServer1Svc -EventName "GetRegisteredServerCompleted" -Action {
                    (New-Event -SourceIdentifier "GetRegisteredServerCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:MonitoringServer1Svc -EventName "RegisterForMonitoringEventPushNotificationsCompleted" -Action {
                    (New-Event -SourceIdentifier "RegisterForMonitoringEventPushNotificationsCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:MonitoringServer1Svc -EventName "DeregisterFromMonitoringEventPushNotificationsCompleted" -Action {
                    (New-Event -SourceIdentifier "DeregisterFromMonitoringEventPushNotificationsCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:MonitoringServer1Svc -EventName "GetPendingNotificationsCompleted" -Action {
                    (New-Event -SourceIdentifier "GetPendingNotificationsCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:MonitoringServer1Svc -EventName "RemovePendingNotificationsCompleted" -Action {
                    (New-Event -SourceIdentifier "RemovePendingNotificationsCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:MonitoringServer1Svc -EventName "IsReadPendingNotificationsCompleted" -Action {
                    (New-Event -SourceIdentifier "IsReadPendingNotificationsCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:MonitoringServer1Svc -EventName "GetMonitoringActionsCompleted" -Action {
                    (New-Event -SourceIdentifier "GetMonitoringActionsCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:MonitoringServer1Svc -EventName "AddOrReplaceMonitoringActionCompleted" -Action {
                    (New-Event -SourceIdentifier "AddOrReplaceMonitoringActionCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:MonitoringServer1Svc -EventName "DeleteMonitoringActionCompleted" -Action {
                    (New-Event -SourceIdentifier "DeleteMonitoringActionCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:MonitoringServer1Svc -EventName "GetMonitoringEventsCompleted" -Action {
                    (New-Event -SourceIdentifier "GetMonitoringEventsCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:MonitoringServer1Svc -EventName "AddOrReplaceMonitoringEventCompleted" -Action {
                    (New-Event -SourceIdentifier "AddOrReplaceMonitoringEventCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:MonitoringServer1Svc -EventName "DeleteMonitoringEventCompleted" -Action {
                    (New-Event -SourceIdentifier "DeleteMonitoringEventCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null
                                
                #endregion

                #region Tableau1
                # WSDL herunterladen...
                [Uri] $UriTableau1 = $Uri.AbsoluteUri + "/WebServices/Tableau1.asmx?wsdl"
                $output = Receive-WSDLFile -Uri $UriTableau1
                $output | Set-Content -Path "$env:TEMP\Tableau1.wsdl"
                $Global:Tableau1Svc = New-WebServiceProxy -Uri "$env:TEMP\Tableau1.wsdl" -Namespace "LCNGVS.Tableau"
                $Global:Tableau1Svc.CookieContainer = $Global:authSvc.CookieContainer

                Register-ObjectEvent -InputObject $Global:Tableau1Svc -EventName "GetTableausCompleted" -Action {
                    (New-Event -SourceIdentifier "GetTableausCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:Tableau1Svc -EventName "OpenTableauCompleted" -Action {
                    (New-Event -SourceIdentifier "OpenTableauCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:Tableau1Svc -EventName "CloseTableauCompleted" -Action {
                    (New-Event -SourceIdentifier "CloseTableauCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:Tableau1Svc -EventName "GetImagesCompleted" -Action {
                    (New-Event -SourceIdentifier "GetImagesCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:Tableau1Svc -EventName "PollUpdatesCompleted" -Action {
                    (New-Event -SourceIdentifier "PollUpdatesCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:Tableau1Svc -EventName "SubmitButtonCompleted" -Action {
                    (New-Event -SourceIdentifier "SubmitButtonCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:Tableau1Svc -EventName "SubmitDimmerCompleted" -Action {
                    (New-Event -SourceIdentifier "SubmitDimmerCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:Tableau1Svc -EventName "GetSupportedTrendLogSourcesCompleted" -Action {
                    (New-Event -SourceIdentifier "GetSupportedTrendLogSourcesCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:Tableau1Svc -EventName "GetTrendLogsCompleted" -Action {
                    (New-Event -SourceIdentifier "GetTrendLogsCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:Tableau1Svc -EventName "CloseTrendLogCompleted" -Action {
                    (New-Event -SourceIdentifier "CloseTrendLogCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:Tableau1Svc -EventName "OpenTrendLogCompleted" -Action {
                    (New-Event -SourceIdentifier "OpenTrendLogCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:Tableau1Svc -EventName "GetTrendLogValuesCompleted" -Action {
                    (New-Event -SourceIdentifier "GetTrendLogValuesCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:Tableau1Svc -EventName "GetTrendLogValuesMultipleCompleted" -Action {
                    (New-Event -SourceIdentifier "GetTrendLogValuesMultipleCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                #endregion

                #region Timer1
                # WSDL herunterladen...
                [Uri] $UriTimer1 = $Uri.AbsoluteUri + "/WebServices/Timer1.asmx?wsdl"
                $output = Receive-WSDLFile -Uri $UriTimer1
                $output | Set-Content -Path "$env:TEMP\Timer1.wsdl"
                $Global:Timer1Svc = New-WebServiceProxy -Uri "$env:TEMP\Timer1.wsdl" -Namespace "LCNGVS.Timer"
                $Global:Timer1Svc.CookieContainer = $Global:authSvc.CookieContainer

                # EventHandler erzeugen
                Register-ObjectEvent -InputObject $Global:Timer1Svc -EventName "IsEnabledCompleted" -Action {
                    (New-Event -SourceIdentifier "IsEnabledCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:Timer1Svc -EventName "SetEnabledCompleted" -Action {
                    (New-Event -SourceIdentifier "SetEnabledCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:Timer1Svc -EventName "GetTimerEventsCompleted" -Action {
                    (New-Event -SourceIdentifier "GetTimerEventsCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:Timer1Svc -EventName "AddOrReplaceTimerCompleted" -Action {
                    (New-Event -SourceIdentifier "AddOrReplaceTimerCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:Timer1Svc -EventName "DeleteTimerCompleted" -Action {
                    (New-Event -SourceIdentifier "DeleteTimerCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                #endregion

                #region AppSiri
                # WSDL herunterladen...
                [Uri] $UriAppSiri = $Uri.AbsoluteUri + "/WebServices/AppSiri.asmx?wsdl"
                $output = Receive-WSDLFile -Uri $UriAppSiri
                $output | Set-Content -Path "$env:TEMP\AppSiri.wsdl"
                $Global:AppSiriSvc = New-WebServiceProxy -Uri "$env:TEMP\AppSiri.wsdl" -Namespace "LCNGVS.AppSiri"
                $Global:AppSiriSvc.CookieContainer = $Global:authSvc.CookieContainer

                # EventHandler erzeugen
                Register-ObjectEvent -InputObject $Global:AppSiriSvc -EventName "LoaddicCompleted" -Action {
                    (New-Event -SourceIdentifier "LoaddicCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:AppSiriSvc -EventName "CommandExecuteCompleted" -Action {
                    (New-Event -SourceIdentifier "CommandExecuteCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:AppSiriSvc -EventName "dimmingCommandCompleted" -Action {
                    (New-Event -SourceIdentifier "dimmingCommandCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:AppSiriSvc -EventName "changeBrightnessCommandCompleted" -Action {
                    (New-Event -SourceIdentifier "changeBrightnessCommandCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:AppSiriSvc -EventName "absRegulatorCommandCompleted" -Action {
                    (New-Event -SourceIdentifier "absRegulatorCommandCompleted" -Sender $args[0] -EventArguments $args[1])
                } | Out-Null

                Register-ObjectEvent -InputObject $Global:AppSiriSvc -EventName "relRegulatorCommandCompleted" -Action {
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
            if ($Global:LCNGVSSession)
            {
                $Global:LCNGVSSession | Add-Member -MemberType NoteProperty -Name UserName -Value $Credential.UserName
                $Global:LCNGVSSession
            }
        }
    }
    End
    {
    }
}

# Alias: 'Logout-LCNGVSServer'
function Disconnect-LCNGVS
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
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Authentification", $Global:LCNGVS_Dictionary.DisconnectLCNGVS))
        {
            if ($Global:LCNGVSSession.isSuccess)
            {
                try
                {                    
                    $Global:authSvc.Logout()
                    $Global:LCNGVSSession.isSuccess = $false
                }
                catch [System.Exception]
                {
                    Write-Error -Message $_
                }
                finally
                {
                    $Global:LCNGVSSession
                }
            }
            else
            {
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

# Alias: 'Logout-LCNGVSServerAsync'
function Disconnect-LCNGVSAsync
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
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Authentification", $Global:LCNGVS_Dictionary.DisconnectLCNGVS))
        {
            if ($Global:LCNGVSSession.isSuccess)
            {
                try
                {                    
                    $Global:authSvc.LogoutAsync()
                }
                catch [System.Exception]
                {
                    Write-Error -Message $_
                }
            }
            else
            {
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

function Get-LCNGVSSession
{
    [CmdletBinding(DefaultParameterSetName='Default', 
        SupportsShouldProcess=$true, 
        PositionalBinding=$false,
        HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSSession',
        ConfirmImpact='Medium')]
    [Alias()]
    [OutputType()]
    Param(
    )

    Begin
    {
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Authentification", $Global:LCNGVS_Dictionary.GetLCNGVSSession))
        {
            if ($Global:LCNGVSSession.isSuccess)
            {
                try
                {                    
                    $Global:LCNGVSSession
                }
                catch [System.Exception]
                {
                    Write-Error -Message $_
                }
            }
            else
            {
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

function Get-LCNGVSUserRights
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSUserRights',
                  ConfirmImpact='Medium')]
    [Alias('usrr')]
    [OutputType([String[]])]
    Param(
    )

    Begin
    {
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Authentification", $Global:LCNGVS_Dictionary.GetLCNGVSUserRights))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $UserRights = $Global:LCNGVSSession.UserRights
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
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
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

function Get-LCNGVSServerInfo
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSServerInfo',
                  ConfirmImpact='Medium')]
    [Alias('svrinfo')]
    [OutputType([LCNGVS.Authentification.ServerInfo])]
    Param(
    )

    Begin
    {
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Authentification", $Global:LCNGVS_Dictionary.GetLCNGVSServerInfo))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $ServerInfo = $Global:authSvc.GetServerInfo()
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
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
            }
        }        
    }
    End
    {
    }
}

function Get-LCNGVSServerInfoAsync
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSServerInfo',
                  ConfirmImpact='Medium')]
    [Alias('svrinfoa')]
    [OutputType([LCNGVS.Authentification.ServerInfo])]
    Param(
    )

    Begin
    {
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Authentification", $Global:LCNGVS_Dictionary.GetLCNGVSServerInfo))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Global:authSvc.GetServerInfoAsync()
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
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
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Authentification", $Global:LCNGVS_Dictionary.GetLCNGVSRecentTableauList))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Strings = $Global:LCNGVSSession.CustomData.Strings
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                    $Strings
                }
            }
            else
            {
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

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
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Authentification", $Global:LCNGVS_Dictionary.GetLCNGVSLastTableauUri))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Strings = $Global:LCNGVSSession.CustomData.Strings[0].Value
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                    $Strings
                }
            }
            else
            {
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

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
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Authentification", $Global:LCNGVS_Dictionary.GetLCNGVSCustomData))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $CustomData = $Global:LCNGVSSession.CustomData
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
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

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
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Authentification", $Global:LCNGVS_Dictionary.NewLCNGVSCustomData))
        {
            if ($Global:LCNGVSSession.IsSuccess)
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
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

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
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Authentification", $Global:LCNGVS_Dictionary.SetLCNGVSCustomData))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Global:authSvc.SetUserCustomData($CustomData)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
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

# Alias: Get-Status
function Get-LCNGVSServerStatus
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
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Status", $Global:LCNGVS_Dictionary.GetLCNGVSServerStatus))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $LCNStatus = $Global:Status1Svc.GetStatus()
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
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

# Alias: Get-StatusAsync
function Get-LCNGVSServerStatusAsync
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
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Status", $Global:LCNGVS_Dictionary.GetLCNGVSServerStatus))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {
                    $Global:Status1Svc.GetStatusAsync()
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

#endregion

# -----------------------------------------------
# Webservice: MacroServer
# -----------------------------------------------
#region WebService: MacroServer

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
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.MacroServer", $Global:LCNGVS_Dictionary.GetLCNGVSMacroServerEnabled))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Global:MacroServer1Svc.IsEnabled()
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
            }
        }
    }
    End
    {
    }    
}

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
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.MacroServer", $Global:LCNGVS_Dictionary.SetLCNGVSMacroServerEnabled))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Global:MacroServer1Svc.SetEnabled($Enabled)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

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
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.MacroServer", $Global:LCNGVS_Dictionary.GetLCNGVSMacro))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $MacroList = $Global:MacroServer1Svc.GetMacros()
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
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

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
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.MacroServer", $Global:LCNGVS_Dictionary.GetLCNGVSMacro))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Global:MacroServer1Svc.GetMacrosAsync()
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

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
        [String] $macroName
    )

    Begin
    {
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.MacroServer", $Global:LCNGVS_Dictionary.InvokeLCNGVSMacro))
        {   
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Global:MacroServer1Svc.ExecuteMacro($macroName)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

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
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.MacroServer", $Global:LCNGVS_Dictionary.InvokeLCNGVSMacro))
        {   
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Global:MacroServer1Svc.ExecuteMacroAsync($macroName)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

#endregion

# -----------------------------------------------
# Webservice: Tableau
# -----------------------------------------------
#region WebService: Tableau

# Alias: Get-Tableaus
function Get-LCNGVSTableauGroupInfo
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
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {      
        if ($pscmdlet.ShouldProcess("LCNGVS.Tableau", "get TableauGroupInfo"))
        {   
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $TableauGroupInfoList = $Global:Tableau1Svc.GetTableaus()
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
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
            }
        }
    }
    End
    {        
    }
}

# Alias: Open-Tableau
function Get-LCNGVSTableau
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSTableau',
                  ConfirmImpact='Medium')]
    [Alias('Open-LCNGVSTableau','Open-Tableau')]
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
                   Position=1,
                   ParameterSetName='Uri')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String] $TableauUri
    )

    Begin
    {
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }

        if ($pscmdlet.ParameterSetName -eq 'Uri')
        { 
            [String[]] $string = $TableauUri.Split('\')
            $tableauGroupName = $string[0]
            $tableauId = $string[1]
        }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Tableau", "get tableau with id [$($tableauId)] from group [$($tableauGroupName)]"))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Tableau = $Global:Tableau1Svc.OpenTableau($tableauGroupName, $tableauId)
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
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

# Alias: Close-Tableau
function Close-LCNGVSTableau
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
        [String] $tableauSessionId
    )

    Begin
    {
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Tableau", "close tableau"))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Global:Tableau1Svc.CloseTableau($tableauSessionId)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

# Alias: Get-Images
function Get-LCNGVSImageList
{
    [CmdletBinding(DefaultParameterSetName='Standard', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSImage',
                  ConfirmImpact='Medium')]
    [Alias('Get-Images')]
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
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Tableau", "get image"))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Image = $Global:Tableau1Svc.GetImages($imageName)
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
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

# Alias: Poll-Updates
function Get-LCNGVSControlUpdateList
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
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Tableau", "poll updates"))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Control = $Global:Tableau1Svc.PollUpdates($tableauSessionId,$updatedControls,$updatedControlStringIds)
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
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

# Alias: Submit-Button
function Invoke-LCNGVSButton
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
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Tableau", $Global:LCNGVS_Dictionary.InvokeLCNGVSButton))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $SubmitResult = $Global:Tableau1Svc.SubmitButton($tableauSessionId, $controllId)
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
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

# Alias: Submit-Dimmer
function Invoke-LCNGVSDimmer
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
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Tableau", $Global:LCNGVS_Dictionary.InvokeLCNGVSDimmer))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $SubmitResult = $Global:Tableau1Svc.SubmitDimmer($tableauSessionId, $controllId, $positionInPercent)
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
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
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
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {        
        if ($pscmdlet.ShouldProcess("LCNGVS.Tableau", $Global:LCNGVS_Dictionary.LCNGVSSupportedTrendLogSources))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $TrendLogSources = $Global:Tableau1Svc.GetSupportedTrendLogSources($busId,$segId,$modId)
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
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
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
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Tableau", $Global:LCNGVS_Dictionary.GetLCNGVSTrendLog))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $TrendLogItem = $Global:Tableau1Svc.GetTrendLogs()
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
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

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
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Tableau", $Global:LCNGVS_Dictionary.ExportLCNGVSTrendLog))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    [Uri] $url = $Global:authSvc.Url
                    $BasisUrl = $url.Scheme + "://" + $url.Host + $url.Segments[0] + $url.Segments[1]
                    $BasisUrl = $BasisUrl + "TrendLogExport.aspx?busId=$($busId)&segId=$($segId)&modId=$($modId)&source=$($source)&start=$($StartDate.Year)-$($StartDate.Month.ToString('00'))-$($StartDate.Day.ToString('00'))&end=$($EndDate.Year)-$($EndDate.Month.ToString('00'))-$($EndDate.Day.ToString('00'))"
                    $webrequest = [System.Net.HTTPWebRequest]::Create($BasisUrl);
                    $webrequest.CookieContainer = $Global:authSvc.CookieContainer
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
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
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
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Tableau", $Global:LCNGVS_Dictionary.GetLCNGVSTrendLog))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Guid = $Global:Tableau1Svc.OpenTrendLog($busId,$segId,$modId,$source,$logPeriodDays,$inactivityTimeoutSecs)
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
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
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
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Tableau", $Global:LCNGVS_Dictionary.GetLCNGVSTrendLog))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    [bool] $bool = $Global:Tableau1Svc.CloseTrendLog($Id)
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
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
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
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Tableau", $Global:LCNGVS_Dictionary.GetLCNGVSTrendLog))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $TrendLog = $Global:Tableau1Svc.GetTrendLogValues($Id,$start,$end,$scaleUnit,$intervalSecs)
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
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
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
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Tableau", $Global:LCNGVS_Dictionary.GetLCNGVSTrendLog))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $TrendLog = $Global:Tableau1Svc.GetTrendLogValuesMultiple($TrendLogRanges,$scaleUnit,$intervalSecs)
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
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

#endregion

# -----------------------------------------------
# Webservice: MonioringServer - Ereignismelder
# -----------------------------------------------
#region WebService: MonitoringServer

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
    )

    Begin
    {
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.MonitoringServer", "Get Monitoring Events"))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Global:MonitoringServer1Svc.GetMonitoringEvents()
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
            }
        }
    }
    End
    {
    }    
}

function Get-LCNGVSMonitoringActions
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
    )

    Begin
    {
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.MonitoringServer", "Get Monitoring Events"))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Global:MonitoringServer1Svc.GetMonitoringActions()
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
            }
        }
    }
    End
    {
    }    
}

function Remove-LCNGVSMonitoringActions
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSMonitoringActions',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([bool])]
    param
    (
        [String] $Id,
        [bool] $ForceDeletion
    )

    Begin
    {
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.MonitoringServer", "Remove a monitoring Action"))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Global:MonitoringServer1Svc.DeleteMonitoringAction($Id, $ForceDeletion)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
            }
        }
    }
    End
    {
    }    
}

function Remove-LCNGVSMonitoringEvent
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSMonitoringActions',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([bool])]
    param
    (
        [String] $Id
    )

    Begin
    {
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.MonitoringServer", "Remove a Monitoring Event"))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Global:MonitoringServer1Svc.DeleteMonitoringEvent($Id)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
            }
        }
    }
    End
    {
    }    
}

# ToDo:
# -------------------
# AddOrReplaceMonitoringAction()
# AddOrReplaceMonitoringEvent()
# DeregisterDevice()
# DeregisterFromMonitoringEventPushNotifications()
# GetPendingNotifications()
# GetRegisteredDevice()
# GetRegisteredServer()
# ...

#endregion

# -----------------------------------------------
# Webservice: AppSiri - Sprachsteuerung
# -----------------------------------------------
#region WebService: AppSiri

# Alias: Load-dic
function Get-LCNGVSAppSiriItem
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
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.AppSiri", "load SiriItemWebService dictionary"))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $items = $Global:AppSiriSvc.Loaddic()
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
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

# Alias: Load-dicAsync
function Get-LCNGVSAppSiriItemAsync
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
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.AppSiri", "load SiriItemWebService dictionary"))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Global:AppSiriSvc.LoaddicAsync()
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

# Alias: Execute-Command
function Invoke-LCNGVSAppSiriCommand
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Invoke-LCNGVSAppSiriItem',
                  ConfirmImpact='Medium')]
    [Alias('Execute-Command')]
    [OutputType([bool])]
    param(
        $itemTitle,
        $listSpeechIntent
    )

    Begin
    {
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.AppSiri", "invoke SiriItem"))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Global:AppSiriSvc.CommandExecute($itemTitle, $listSpeechIntent)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
            }
        }
    }
    End
    {
    }    
}

function Invoke-LCNGVSAppSiriCommandAsync
{
    [CmdletBinding(DefaultParameterSetName='Default', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Invoke-LCNGVSAppSiriCommandAsync',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([bool])]
    param(
        $itemTitle,
        $listSpeechIntent
    )

    Begin
    {
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.AppSiri", "invoke SiriItem"))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Global:AppSiriSvc.CommandExecuteAsync($itemTitle, $listSpeechIntent)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
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
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.AppSiri", "invoke SiriItem"))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Global:AppSiriSvc.dimmingCommand($itemTitle, $listSpeechIntent, $value)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
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
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.AppSiri", "invoke SiriItem"))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Global:AppSiriSvc.dimmingCommandAsync($itemTitle, $listSpeechIntent, $value)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
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
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.AppSiri", "invoke SiriItem"))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Global:AppSiriSvc.absRegulatorCommand($itemTitle, $listSpeechIntent, $value)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
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
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.AppSiri", "invoke SiriItem"))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Global:AppSiriSvc.absRegulatorCommandAsync($itemTitle, $listSpeechIntent, $value)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
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
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.AppSiri", "invoke SiriItem"))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Global:AppSiriSvc.relRegulatorCommand($itemTitle, $listSpeechIntent, $value, $add)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
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
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.AppSiri", "invoke SiriItem"))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Global:AppSiriSvc.relRegulatorCommandAsync($itemTitle, $listSpeechIntent, $value, $add)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
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
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.AppSiri", "invoke SiriItem"))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Global:AppSiriSvc.changeBrightnessCommand($itemTitle, $listSpeechIntent, $value, $add)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
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
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.AppSiri", "invoke SiriItem"))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {            
                    $Global:AppSiriSvc.changeBrightnessCommandAsync($itemTitle, $listSpeechIntent, $value, $add)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
            }
            else
            {
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
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
        [DateTime] $StartDate,
        [datetime] $EndDate,
        
        [ValidateSet("Server", "Access", "Macro", "Timer", "LCNGVS")]
        [String] $LogType
    )

    Begin
    {
        if ( -not ($Global:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Logs", "get log"))
        {
            if ($Global:LCNGVSSession.IsSuccess)
            {
                try
                {
                    $logs = $null

                    switch ($LogType)
                    {
                        'Server' { $logs = $Global:Logs1Svc.GetLogLcnServer($StartDate,$EndDate) }
                        'Access' { $logs = $Global:Logs1Svc.GetLogAccessControl($StartDate,$EndDate) }
                        'Macro'  { $logs = $Global:Logs1Svc.GetLogMacroServer($StartDate,$EndDate) }
                        'Timer'  { $logs = $Global:Logs1Svc.GetLogTimer($StartDate,$EndDate) }
                        'LCNGVS' { $logs = $Global:Logs1Svc.GetLogLCNGVS($StartDate,$EndDate) }
                        Default  { $logs = $Global:Logs1Svc.GetLogLCNGVS($StartDate,$EndDate) }
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
                Write-Error -Message $Global:LCNGVS_Dictionary.ErrorMessage1
            }
        }
    }
    End
    {
    }
}

#endregion