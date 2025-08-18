<#
.SYNOPSIS
    Add Lapsuser

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
    We Enhanced Add Lapsuser

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


$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

.SYNOPSIS
Creates a local user account with a randomly generated password and adds it to the local Administrators group to be targeted by LAPS.

.DESCRIPTION
This script was made for use with Intune but can be adapted. This script creates a new local user account with a 10-character random password. The account is added to the local Administrators group. The password is set to never expire for convenience, making this script useful in scenarios like implementing Local Administrator Password Solution (LAPS) configurations.
Deploy this script from Intune as a Platform script. Run as system.

.PARAMETERS
None.

.PREREQUISITES
- The script must be run with administrative privileges.
- Modify the `$WEUsername` variable to set the desired account name before running the script.

.NOTES
- The script sets a random password using alphanumeric characters (A-Z, a-z, 0-9).
- By default, the execution policy is bypassed for the session to ensure the script runs without restrictions.
- Script checks if account already exists and exits without changes if it does.
- Designed for automated deployment through Intune with no user interaction.
- Ensure the account creation complies with your organization's policies for local administrator accounts.

.EXAMPLE

.\Add-LAPSuser.ps1



$WELogFilePath = Join-Path -Path $env:TEMP -ChildPath " ScriptLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function WE-Write-Log {
    

function Write-WELog {
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
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

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEMessage,
        [string]$WEType = " INFO"
    )
    $WETimestamp = Get-Date -Format " yyyy-MM-dd HH:mm:ss"
    $WELogMessage = " [$WETimestamp] [$WEType] $WEMessage"
    
    # Write to the console
    switch ($WEType) {
        " ERROR" { Write-Host $WELogMessage -ForegroundColor Red }
        " WARNING" { Write-Host $WELogMessage -ForegroundColor Yellow }
        default { Write-Host $WELogMessage }
    }
    
    Add-Content -Path $WELogFilePath -Value $WELogMessage
}

Write-Log " Add-LAPSuser.ps1 started..."

try {
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
    Write-Log " Execution policy set to Bypass for current process"
} 
catch {
    Write-Log " Failed to set execution policy: $_" -Type " ERROR"
    exit 1
}

$WEUsername = " local.scs"
$password = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 10 | ForEach-Object {[char]$_})

Write-Log " Checking if user $WEUsername already exists..."
if (Get-LocalUser -Name $WEUsername -ErrorAction SilentlyContinue) {
    Write-Log " User $WEUsername already exists! No changes made." -Type " INFO"
    Write-Log " Script execution completed - account already exists"
    exit 0
} 
else {
    Write-Log " Creating new LAPS account..."
    try {
       ;  $WEUser = New-LocalUser -Name $WEUsername -Password (ConvertTo-SecureString -String $password -AsPlainText -Force) -PasswordNeverExpires -ErrorAction Stop
        Write-Log " User account $WEUsername created successfully!"
        Write-Log " Password: $password" -Type " INFO"
        
        try {
           ;  $WEGroup = Get-LocalGroup -Name " Administrators"
            Add-LocalGroupMember -Group $WEGroup -Member $WEUser -ErrorAction Stop
            Write-Log " User $WEUsername added to Administrators group"
            Write-Log " LAPS account creation completed successfully!"
        }
        catch {
            Write-Log " Failed to add user to Administrators group: $_" -Type " ERROR"
            Write-Log " Attempting to clean up by removing the created user account..." -Type " WARNING"
            
            try {
                Remove-LocalUser -Name $WEUsername -ErrorAction Stop
                Write-Log " User account $WEUsername removed successfully" -Type " INFO"
            }
            catch {
                Write-Log " Failed to remove user account: $_" -Type " ERROR"
            }
            
            exit 1
        }
    }
    catch {
        Write-Log " Failed to create user account: $_" -Type " ERROR"
        exit 1
    }
}

Write-Log " Script execution completed"


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================