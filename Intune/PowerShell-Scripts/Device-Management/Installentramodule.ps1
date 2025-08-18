<#
.SYNOPSIS
    Installentramodule

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
    We Enhanced Installentramodule

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


Install-PackageProvider -Name NuGet -Force
Install-Module -Name Microsoft.Graph.Entra -Repository PSGallery -Force -AllowPreRelease


$WEErrorActionPreference = "Stop"; 
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

Install-PackageProvider -Name NuGet -Force
Install-Module -Name PowerShellGet -Force -AllowClobber

Remove-Module PowerShellGet,PackageManagement -Force

Import-Module PowerShellGet -MinimumVersion 2.0 -Force
Import-PackageProvider PowerShellGet -MinimumVersion 2.0 -Force
; 
$requiredModules = @(
    " Microsoft.Graph.DirectoryObjects" ,
    " Microsoft.Graph.Users" ,
    " Microsoft.Graph.Groups" ,
    " Microsoft.Graph.Users.Actions" ,
    " Microsoft.Graph.Users.Functions" ,
    " Microsoft.Graph.Identity.DirectoryManagement" ,
    " Microsoft.Graph.Identity.SignIns" ,
    " Microsoft.Graph.Governance" ,
    " Microsoft.Graph.Applications"
)

foreach($module in $requiredModules)
{
    if(!(Get-Module -Name $module -ListAvailable))
    {
        Install-Module -Name $module -Force -AllowClobber
    }
}

Install-Module -Name Microsoft.Graph.Entra -Repository PSGallery -Force -AllowPreRelease


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================