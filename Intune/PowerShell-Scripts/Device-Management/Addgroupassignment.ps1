<#
.SYNOPSIS
    Addgroupassignment

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
    We Enhanced Addgroupassignment

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


$policyId = "<YOUR POLICY OBJECT ID>"



$WEErrorActionPreference = " Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

$policyId = " <YOUR POLICY OBJECT ID>"
$targetGroup = " <YOUR GROUP OBJECT ID>"

$getUri = " https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$($policyId)/assignments"
$postUri = " https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$($policyId)/microsoft.graph.assign"

Connect-MgGraph

try {
    $assignments = Invoke-MgGraphRequest -Method GET -Uri $getUri    
}
catch {
    Write-Warning $_.Exception.Message
}

$groupAssignments = @($assignments.value | Where-Object { $_.target.'@odata.type' -eq " #microsoft.graph.groupAssignmentTarget" })

$alreadyAssigned = $groupAssignments | Where-Object { $_.target.groupId -eq $targetGroup }

if(-not $alreadyAssigned){
   ;  $groupAssignments = $groupAssignments + [PSCustomObject]@{
        target = @{
            " @odata.type" = " #microsoft.graph.groupAssignmentTarget"
            groupId = $targetGroup
        }
    }
}
; 
$body = @{
    assignments = $groupAssignments | ForEach-Object {
        @{
            target = @{
                " @odata.type" = $_.target.'@odata.type'
                groupId = $_.target.groupId
            }
        }
    }
} | ConvertTo-Json -Depth 10

try {
    Invoke-MgGraphRequest -Method POST -Uri $postUri -Body $body -ContentType " application/json"
}
catch {
    Write-Warning $_.Exception.Message
}



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================