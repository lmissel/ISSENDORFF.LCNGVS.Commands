
Import-Module ISSENDORFF.LCNGVS.Commands

Connect-LCNGVS -Uri "http://access.lcn.de/LCNGVSDemo" -Credential (Microsoft.PowerShell.Security\Get-Credential -UserName guest -Message "Bitte geben Sie das Kennwort ein. Kennwort: lcn")

$tableauGroupName = 'Demo House'
$tableauId = 'Desktop View'
$GaragentorAufControlId = 38
$GaragentorZuControlId = 194

$tableau = Open-LCNGVSTableau -tableauGroupName $tableauGroupName -tableauId $tableauId

Invoke-LCNGVSButton -tableauSessionId $tableau.tableauSessionId -controllId $GaragentorAufControlId

sleep -Seconds 5

Invoke-LCNGVSButton -tableauSessionId $tableau.tableauSessionId -controllId $GaragentorZuControlId

Close-LCNGVSTableau $tableau.tableauSessionId

Disconnect-LCNGVS