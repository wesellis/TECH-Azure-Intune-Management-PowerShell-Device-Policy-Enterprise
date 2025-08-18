<#
.SYNOPSIS
    Installchromeifoobecomplete

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
    We Enhanced Installchromeifoobecomplete

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


$WEDefinition = @"



$WEErrorActionPreference = " Stop"; 
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')
try {
    # Main script execution
) { " Continue" } else { " SilentlyContinue" }
; 
$WEDefinition = @"

using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Api
{
    public class Kernel32
    {
        [DllImport(" kernel32.dll" , CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int OOBEComplete(ref int bIsOOBEComplete);
    }
}
" @

function log
{
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [string]$message
    )
    $time = Get-Date -Format " yyyy-MM-dd HH:mm:ss tt"
    $output = " $time - $message"
    Write-Output $output
}

Add-Type -TypeDefinition $WEDefinition -Language CSharp
; 
$WEIsOOBEComplete = $false
[void][Api.Kernel32]::OOBEComplete([ref] $WEIsOOBEComplete)
; 
$logFile = " C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\ChromeInstaller.log"

if(-not(Test-Path $logFile))
{
    New-Item -Path $logFile -ItemType File -Force | Out-Null
}

Start-Transcript -Path $logFile -Verbose -Append

log " IsOOBEComplete variable is equal to $($WEIsOOBEComplete)"

if(-not $WEIsOOBEComplete)
{
    log " OOBE is not complete. Skipping Chrome install."
    Exit 0 # Intune will retry later
}

log " OOBE complete. Installing Chrome..."

Start-Process -FilePath " $($WEPSScriptRoot)\GoogleChromeStandaloneEnterprise64.msi" -ArgumentList " /qn" -Wait -NoNewWindow

log " Chrome installation completed."

Stop-Transcript
Exit 0




} catch {
    Write-Error " Script execution failed: $($_.Exception.Message)"
    throw
}
