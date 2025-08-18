<#
.SYNOPSIS
    Export Statedevices

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
    We Enhanced Export Statedevices

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


<#
    .SYNOPSIS
        List users and devices including last login time stamp.

    .NOTES
        Author: Aaron Parker
        Twitter: @stealthpuppy

    .LINK
        https://stealthpuppy.com



$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
Param ()
; 
$WEUsers = Get-AzureADUser -All $true | Select-Object UserPrincipalName, ObjectId
ForEach ($WEUser in $WEUsers) {
    Get-AzureADUserRegisteredDevice -ObjectId $user.ObjectId | ForEach-Object {
       ;  $WEOutput = [PSCustomObject] @{
            DeviceOwner                   = $user.UserPrincipalName
            DeviceName                    = $_.DisplayName
            DeviceOSType                  = $_.DeviceOSType
            ApproximateLastLogonTimeStamp = $_.ApproximateLastLogonTimeStamp
        }
        Write-Output -InputObject $WEOutput
    }
}





# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================