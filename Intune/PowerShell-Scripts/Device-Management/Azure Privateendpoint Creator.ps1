<#
.SYNOPSIS
    Azure Privateendpoint Creator

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
    We Enhanced Azure Privateendpoint Creator

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
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')
try {
    # Main script execution
) { " Continue" } else { " SilentlyContinue" }



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
    [Parameter(Mandatory=$true)]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEResourceGroupName,
    
    [Parameter(Mandatory=$true)]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEEndpointName,
    
    [Parameter(Mandatory=$true)]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WESubnetId,
    
    [Parameter(Mandatory=$true)]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WETargetResourceId,
    
    [Parameter(Mandatory=$true)]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEGroupId,
    
    [Parameter(Mandatory=$true)]
    [string]$WELocation
)

Write-WELog " Creating Private Endpoint: $WEEndpointName" " INFO"

; 
$WEPrivateLinkServiceConnection = New-AzPrivateLinkServiceConnection `
    -Name " $WEEndpointName-connection" `
    -PrivateLinkServiceId $WETargetResourceId `
    -GroupId $WEGroupId
; 
$WEPrivateEndpoint = New-AzPrivateEndpoint `
    -ResourceGroupName $WEResourceGroupName `
    -Name $WEEndpointName `
    -Location $WELocation `
    -Subnet @{Id=$WESubnetId} `
    -PrivateLinkServiceConnection $WEPrivateLinkServiceConnection

Write-WELog " ✅ Private Endpoint created successfully:" " INFO"
Write-WELog "  Name: $($WEPrivateEndpoint.Name)" " INFO"
Write-WELog "  Location: $($WEPrivateEndpoint.Location)" " INFO"
Write-WELog "  Target Resource: $($WETargetResourceId.Split('/')[-1])" " INFO"
Write-WELog "  Group ID: $WEGroupId" " INFO"
Write-WELog "  Private IP: $($WEPrivateEndpoint.NetworkInterfaces[0].IpConfigurations[0].PrivateIpAddress)" " INFO"

Write-WELog " `nNext Steps:" " INFO"
Write-WELog " 1. Configure DNS records for the private endpoint" " INFO"
Write-WELog " 2. Update network security groups if needed" " INFO"
Write-WELog " 3. Test connectivity from the virtual network" " INFO"




} catch {
    Write-Error " Script execution failed: $($_.Exception.Message)"
    throw
}
