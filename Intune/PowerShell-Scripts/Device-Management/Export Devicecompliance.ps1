<#
.SYNOPSIS
    Export Devicecompliance

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
    We Enhanced Export Devicecompliance

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
        Compile a report on per device compliance settings



$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')
try {
    # Main script execution
) { " Continue" } else { " SilentlyContinue" }

[CmdletBinding()]
$ErrorActionPreference = " Stop"


function Write-WELog {
    param(
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$Message,
        [ValidateSet(" INFO" , " WARN" , " ERROR" , " SUCCESS" )]
        [string]$Level = " INFO"
    )
    
   ;  $timestamp = Get-Date -Format " yyyy-MM-dd HH:mm:ss"
   ;  $colorMap = @{
        " INFO" = " Cyan" ; " WARN" = " Yellow" ; " ERROR" = " Red" ; " SUCCESS" = " Green"
    }
    
    $logEntry = " $timestamp [WE-Enhanced] [$Level] $Message"
    Write-Host $logEntry -ForegroundColor $colorMap[$Level]
}

param ()

<#

$authparams = @{
    ClientId     = " db8dbb7a-40a4-444b-8912-6f14f80816b7"
    TenantId     = " tenant.onmicrosoft.com"
    ClientSecret = (" sdflkjsdflkjsdfsdfsdfsdfsdf" | ConvertTo-SecureString -AsPlainText -Force)
}
$auth = Get-MsalToken @authParams


$settings = @(
    " Windows10CompliancePolicy.ActiveFirewallRequired" ,
    " Windows10CompliancePolicy.AntiSpywareRequired" ,
    " Windows10CompliancePolicy.AntivirusRequired" ,
    " Windows10CompliancePolicy.BitLockerEnabled" ,
    " Windows10CompliancePolicy.CodeIntegrityEnabled" ,
    " Windows10CompliancePolicy.DefenderEnabled" ,
    " Windows10CompliancePolicy.OsMinimumVersion" ,
    #" Windows10CompliancePolicy.PasswordBlockSimple" ,
    #" Windows10CompliancePolicy.PasswordMinimumLength" ,
    #" Windows10CompliancePolicy.PasswordMinutesOfInactivityBeforeLock" ,
    #" Windows10CompliancePolicy.PasswordPreviousPasswordBlockCount" ,
    " Windows10CompliancePolicy.RtpEnabled" ,
    " Windows10CompliancePolicy.SecureBootEnabled" ,
    " Windows10CompliancePolicy.SignatureOutOfDate" ,
    " Windows10CompliancePolicy.StorageRequireEncryption" ,
    " Windows10CompliancePolicy.TpmRequired"
)

Remove-Variable -Name ComplianceTable -ErrorAction " SilentlyContinue"
ForEach ($setting in $settings) {
    $WEUrl = " https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicySettingStateSummaries/$setting/deviceComplianceSettingStates"
    $params = @{
        Headers = @{Authorization = " Bearer $($auth.AccessToken)" }
        Uri     = $WEUrl
        Method  = " Get"
    }
    $query = Invoke-RestMethod @params

    If ($WENull -eq $WEComplianceTable) {
        [System.Array] $WEComplianceTable = @()
        ForEach ($item in $query.value) {
            #Write-WELog " Add $($item.setting) to $($item.deviceName)." " INFO"
            $device = [PSCustomObject] @{
                deviceId          = $item.deviceId
                deviceName        = $item.deviceName
                userPrincipalName = $item.userPrincipalName
                deviceModel       = $item.deviceModel
            }
            $device | Add-Member -NotePropertyName $($item.setting) -NotePropertyValue $item.state -Force
           ;  $WEComplianceTable = $WEComplianceTable + $device
        }
    }
    Else {
        ForEach ($item in $query.value) {
           ;  $index = [array]::IndexOf($WEComplianceTable.deviceId, $item.deviceId)
            If ($WEComplianceTable[$index].PSObject.Properties.name -contains $($item.setting)) {
                #Write-WELog " Device $($WEComplianceTable[$index].deviceName) already has property $($item.setting)." " INFO"
            }
            Else {
                $WEComplianceTable[$index] | Add-Member -NotePropertyName $($item.setting) -NotePropertyValue $item.state -Force
            }
        }
    }
}

$WEComplianceTable | Export-Csv -Path " ComplianceTable.csv" -Delimiter " ,"




} catch {
    Write-Error " Script execution failed: $($_.Exception.Message)"
    throw
}
