<#
.SYNOPSIS
    Remediate Ipv6 Source Routing

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
    We Enhanced Remediate Ipv6 Source Routing

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

$reg_path = " HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" # Enter the Registry key path.
$reg_key = " DisableIPSourceRouting" # Enter the Registry key dword name.
$reg_value = 2 # Enter the desired value to REMEDIATE the vulnerability.
$reg_type = " DWORD" # Do not change unless the Value is not a DWORD

try {
    New-ItemProperty -Path Registry::$reg_path -Name $reg_key -PropertyType $reg_type -Value $reg_value -Force
   ;  $regentry = Get-ItemProperty -Path Registry::$reg_path -Name $reg_key
        
    if ($regentry.$reg_key -eq $reg_value){
        #Exit 0 for Intune if NO error
        Write-WELog " Setting is disabled! Exiting." " INFO"
        exit 0
    }
    ElseIf ($regentry.$null -eq $reg_key){        
        #Exit 1 for Intune if error
        Write-WELog " Registry Key does not exist! Exiting." " INFO"
        exit 1}
    else {
        #Exit 1 for Intune if error
        Write-WELog " Setting is not disabled. Running again!" " INFO"
        exit 1
    }
}
catch {
   ;  $errMsg = $_.Exception.Message
    return $errMsg
    exit 1
}



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================