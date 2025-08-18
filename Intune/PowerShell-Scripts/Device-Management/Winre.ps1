<#
.SYNOPSIS
    Winre

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules
#>

<#
.SYNOPSIS
    We Enhanced Winre

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


Start-Process "reagentc.exe" -ArgumentList " /disable"
diskpart /s " .\unmount.txt"


$WEErrorActionPreference = " Stop"; 
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

Start-Process " reagentc.exe" -ArgumentList " /disable"

Start-Sleep -Seconds 5

Get-Partition | Where-Object -FilterScript {$_.Type -eq " Recovery" } | Remove-Partition -Confirm:$false


Start-Sleep -Seconds 5

diskpart /s " .\recovery.txt"

Start-Sleep -Seconds 5

mkdir " Z:\Recovery\WindowsRE"

Start-Sleep -Seconds 2

Copy-Item " $($psscriptroot)\Winre.wim" " Z:\Recovery\WindowsRE"

Start-Process " reagentc.exe" -ArgumentList '/SetREimage /Path " Z:\Recovery\WindowsRE" '

Start-Sleep -Seconds 5

Start-Process " reagentc.exe" -ArgumentList '/enable'
; 
$partitionNumber = Get-Partition | Where-Object -FilterScript {$_.Type -eq " Recovery" } | Select-Object -ExpandProperty PartitionNumber

(Get-Content " $($psscriptroot)\unmount.txt" ) | ForEach-Object {$_ -replace " <x>" , " $partitionNumber" } | Set-Content " $($psscriptroot)\unmount.txt"

Start-Sleep -Seconds 2

diskpart /s " .\unmount.txt"


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================