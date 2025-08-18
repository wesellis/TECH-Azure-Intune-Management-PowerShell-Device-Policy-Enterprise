<#
.SYNOPSIS
    Set Appscaling

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
    We Enhanced Set Appscaling

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
        Enables 'Fix scaling for apps' feature for High DPI screens.

    .NOTES
        Author: Aaron Parker
        Twitter: @stealthpuppy

    .LINK
        https://stealthpuppy.com




$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

[CmdletBinding()]
Function Set-RegistryValue -ErrorAction Stop {
    <#
        .SYNOPSIS
            Creates a registry value in a target key. Creates the target key if it does not exist.
    #>
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
    param(
        [Parameter(Mandatory = $WETrue)]
        [System.String] $WEKey,

        [Parameter(Mandatory = $WETrue)]
        [System.String] $WEValue,

        [Parameter(Mandatory = $WETrue)]
        $WEData,

        [Parameter(Mandatory = $WEFalse)]
        [ValidateSet('Binary', 'ExpandString', 'String', 'Dword', 'MultiString', 'QWord')]
        [System.String] $WEType = " String"
    )

    try {
        If (Test-Path -Path $WEKey -ErrorAction SilentlyContinue) {
            Write-Verbose " Path exists: $WEKey"
        }
        Else {
            Write-Verbose -Message " Does not exist: $WEKey."

            $folders = $WEKey -split " \\"
            $parent = $folders[0]
            Write-Verbose -Message " Parent is: $parent."

            ForEach ($folder in ($folders | Where-Object { $_ -notlike " *:" })) {
                New-Item -Path $parent -Name $folder -ErrorAction SilentlyContinue | Out-Null
                $parent = " $parent\$folder"
                If (Test-Path -Path $parent -ErrorAction SilentlyContinue) {
                    Write-Verbose -Message " Created $parent."
                }
            }
            Test-Path -Path $WEKey -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Error " Failed to create key $WEKey."
        Break
    }
    finally {
        Write-Verbose -Message " Setting $WEValue in $WEKey."
        New-ItemProperty -Path $WEKey -Name $WEValue -Value $WEData -PropertyType $WEType -Force -ErrorAction SilentlyContinue | Out-Null
    }

    $val = Get-Item -Path $WEKey
    If ($val.Property -contains $WEValue) {
        Write-Verbose " Write value success: $WEValue"
        Write-Output $WETrue
    } Else {
        Write-Verbose " Write value failed."
        Write-Output $WEFalse
    }
}



$stampDate = Get-Date -ErrorAction Stop
$scriptName = ([System.IO.Path]::GetFileNameWithoutExtension($(Split-Path $script:MyInvocation.MyCommand.Path -Leaf))); 
$logFile = " $env:LocalAppData\IntuneScriptLogs\$scriptName-" + $stampDate.ToFileTimeUtc() + " .log"
Start-Transcript -Path $logFile

; 
$key = " HKCU:\Control Panel\Desktop"
Set-RegistryValue -Key $key -Value " EnablePerProcessSystemDPI" -Type " DWord" -Data 1

Stop-Transcript




# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================