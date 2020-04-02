# Beispiel: TV-Steckdose

Dieses Beispiel verwendet das von LCN zur Verfuegung stehende [Demohaus](http://access.lcn.de/LCNGVSDemo). Dieses wird mittels Livecam ueberwacht. Wodurch die Wirksamkeit der Beispiele leicht ueberprueft werden kann. Es wird die Tableaugruppe "Demo House" und das Tableau "Desktop View" verwendet.

In diesem Beispiel wird die Steckdose eingeschaltet bzw. nach 5 Sekunden wieder abgeschaltet. 

## Vergehen
Oeffnen Sie ein Browser und geben Sie die URL (http://access.lcn.de/LCNGVSDemo) in die Adressleiste ein und bestätigen Sie diese mit Enter. Melden Sie sich mit dem Benutzer "Guest" und dem Kennwort "lcn" an. Oeffnen Sie die Tableaugruppe "Demo House" und anschließend das Tableau "Desktop View". Starten Sie das Skript **TV-Steckdose.ps1** und geben Sie erneut das Kennwort **lcn** ein. Sie sehen nun im Browser, wie die Steckdose eingeschaltet bzw. nach 5 Sekunden wieder abgeschaltet wird. 

```PowerShell
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
```
