<#
.SYNOPSIS
    Set Registryvalue

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
    We Enhanced Set Registryvalue

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


[CmdletBinding()]
function WE-Set-RegistryValue -ErrorAction Stop {



$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

[CmdletBinding()]
function WE-Set-RegistryValue -ErrorAction Stop {
    <#
        .SYNOPSIS
            Creates a registry value in a target key. Creates the target key if it does not exist.
    #>
    [CmdletBinding(SupportsShouldProcess)]
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
        if (Test-Path -Path $WEKey -ErrorAction " SilentlyContinue" ) {
            Write-Verbose " Path exists: $WEKey"
        }
        else {
            Write-Verbose -Message " Does not exist: $WEKey."

            $folders = $WEKey -split " \\"
            $parent = $folders[0]
            Write-Verbose -Message " Parent is: $parent."

            foreach ($folder in ($folders | Where-Object { $_ -notlike " *:" })) {
                if ($WEPSCmdlet.ShouldProcess($WEPath, (" New-Item -ErrorAction Stop '{0}'" -f " $parent\$folder" ))) {
                    New-Item -Path $parent -Name $folder -ErrorAction " SilentlyContinue" | Out-Null
                }
               ;  $parent = " $parent\$folder"
                if (Test-Path -Path $parent -ErrorAction " SilentlyContinue" ) {
                    Write-Verbose -Message " Created $parent."
                }
            }
            Test-Path -Path $WEKey -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Error " Failed to create key $WEKey."
        break
    }
    finally {
        Write-Verbose -Message " Setting $WEValue in $WEKey."
        if ($WEPSCmdlet.ShouldProcess($WEPath, (" New-ItemProperty -ErrorAction Stop '{0}'" -f $WEKey))) {
            New-ItemProperty -Path $WEKey -Name $WEValue -Value $WEData -PropertyType $WEType -Force -ErrorAction " SilentlyContinue" | Out-Null
        }
    }

   ;  $val = Get-Item -Path $WEKey
    if ($val.Property -contains $WEValue) {
        Write-Verbose " Write value success: $WEValue"
        Write-Output $WETrue
    } else {
        Write-Verbose " Write value failed."
        Write-Output $WEFalse
    }
}



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================