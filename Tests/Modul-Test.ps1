Import-Module -Name Pester
Import-Module -Name ISSENDORFF.LCNGVS.Commands

$Script:Credentials = [PSCredential]::new("guest", (ConvertTo-SecureString -String "lcn" –AsPlainText -Force))

describe "Allgemeine Tests zum Modul" {

    Context "Komponente: Authentification" {
        it "Check URL" {
            $result = Invoke-WebRequest -Uri "http://access.lcn.de/LCNGVSDemo" -Method Head -TimeoutSec 3
            $result.Statuscode | Should Be 200
        }

        it "Anmelden am Server" {
            Connect-LCNGVS -Uri "http://access.lcn.de/LCNGVSDemo" -Credential $Script:Credentials | Should BeOfType "LCNGVS.Authentification.LoginResult"
        }
    }

    Context "Komponente: Tableau" {
        it "Abrufen aller Tableaus" {
            $ListTableau = Get-LCNGVSTableauList -all
            $ListTableau.Count | Should BeGreaterThan 0
        }

        it "Versucht die TV-Steckdose einzuschalten" {
            {
                $tableauGroupName = 'Demo House'
                $tableauId = 'Desktop View'
                $ControllId = 189

                $tableau = Open-LCNGVSTableau -tableauGroupName $tableauGroupName -tableauId $tableauId

                Invoke-LCNGVSButton -tableauSessionId $tableau.tableauSessionId -controllId $ControllId

                Close-LCNGVSTableau $tableau.tableauSessionId
            } | Should Not Throw
        }

        it "Versucht das Garagentor zu oeffen" {
            {
                $tableauGroupName = 'Demo House'
                $tableauId = 'Desktop View'
                $GaragentorAufControlId = 38

                $tableau = Open-LCNGVSTableau -tableauGroupName $tableauGroupName -tableauId $tableauId

                Invoke-LCNGVSButton -tableauSessionId $tableau.tableauSessionId -controllId $GaragentorAufControlId

                Close-LCNGVSTableau $tableau.tableauSessionId
            } | Should Not Throw
        }
    }

    Context "Komponente: Status" {
        It "Abrufen der Serverinformationen" {
            Get-LCNGVSServerInfo | Should BeOfType "LCNGVS.Authentification.ServerInfo"
        }

        It "Ruft den Zustand aller LCN-BUS-Verbindung ab." {
            (Get-LCNGVSServerLcnBusConnectionState)[0] | Should BeOfType "LCNGVS.Status.LcnBusConnectionState"
        }

        It "Ruft den Zustand der ersten LCN-BUS-Verbindung ab und kontrolliert, ob diese verbunden ist." {
            (Get-LCNGVSServerLcnBusConnectionState)[0].isConnected | Should Be $true
        }
    }

    Context "Komponente: Authentification" {
        it "Abmelden vom Server" {
            Disconnect-LCNGVS | Should BeOfType "LCNGVS.Authentification.LoginResult"
        }
    }
}