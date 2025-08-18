<#
.SYNOPSIS
    Assignmentsbygroup

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
    We Enhanced Assignmentsbygroup

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

$graph = " https://graph.microsoft.com/beta"


$groups = (Invoke-MgGraphRequest -Method GET -Uri " https://graph.microsoft.com/beta/groups?`$select=id,displayName" ).value

$groupSelection = $groups | ForEach-Object {
    [PSCustomObject]@{
        Name    = $_.displayName
        Id      = $_.id
        Raw     = $_
    }
}

$selectedGroup = $groupSelection | ogv -Title " Select a group" -PassThru

if(-not $selectedGroup)
{
    Write-WELog " No group selected." " INFO"
    return
}

$groupId = $selectedGroup.id
Write-WELog " `nSelected Group:`n$($selectedGroup.Name) ($groupId)`n" " INFO" -ForegroundColor Cyan


function WE-Get-AssignedItems
{
    [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$url,
        [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$type,
        [string]$nameField = " displayName"
    )

    $results = @()
    $items = Invoke-MgGraphRequest -Uri $url -Method GET

    foreach ($item in $items.value)
    {
        foreach ($assignment in $item.assignments)
        {
            if($assignment.target.groupId -eq $groupId)
            {
               ;  $results = $results + [PSCustomObject]@{
                    Type = $type
                    Name = $item.$nameField
                }
            }
        }
    }

    return $results
}

; 
$results = @()
$results = $results + Get-AssignedItems -url " $graph/deviceAppManagement/mobileApps?`$expand=assignments" -type " app"
$results = $results + Get-AssignedItems -url " $graph/deviceManagement/deviceConfigurations?`$expand=assignments" -type " Configuration Profiles"; 
$results = $results + Get-AssignedItems -url " $graph/deviceManagement/configurationPolicies?`$expand=assignments" -type " Settings Catalog Policy" -nameField " name"


if($results.Count -eq 0)
{
    Write-WELog " No assignments found for this group." " INFO"
}
else 
{
    $results | Sort-Object Type, Name | Format-Table Type, Name -AutoSize
}




} catch {
    Write-Error " Script execution failed: $($_.Exception.Message)"
    throw
}
