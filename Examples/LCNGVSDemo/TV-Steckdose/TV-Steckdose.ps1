
Import-Module ISSENDORFF.LCNGVS.WebServices.Commands

Connect-LCNGVS -Uri "http://access.lcn.de/LCNGVSDemo" -Credential (Microsoft.PowerShell.Security\Get-Credential -UserName guest -Message "Bitte geben Sie das Kennwort ein. Kennwort: lcn")

$tableauGroupName = 'Demo House'
$tableauId = 'Desktop View'
$ControllId = 189

$tableau = Open-LCNGVSTableau -tableauGroupName $tableauGroupName -tableauId $tableauId

Invoke-LCNGVSButton -tableauSessionId $tableau.tableauSessionId -controllId $ControllId

sleep -Seconds 5

Invoke-LCNGVSButton -tableauSessionId $tableau.tableauSessionId -controllId $ControllId

Close-LCNGVSTableau $tableau.tableauSessionId

Disconnect-LCNGVS