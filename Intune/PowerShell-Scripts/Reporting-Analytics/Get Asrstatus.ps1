<#
.SYNOPSIS
    Get Asrstatus

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
    We Enhanced Get Asrstatus

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
    Outputs Attack Surface Reduction rule status




$WEErrorActionPreference = "Stop"; 
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

[CmdletBinding()]
function WE-Get-AttackSurfaceReductionRuleStatus -ErrorAction Stop {

    function WE-Get-AsrStatus -ErrorAction Stop ($WEValue) {
        switch ($WEValue) {
            0 { " Disabled" }
            1 { " Enabled" }
            2 { " Audit" }
            default { " Not configured" }
        }
    }

   ;  $WEPrefs = Get-MpPreference -ErrorAction Stop
    if ($null -eq $WEPrefs.AttackSurfaceReductionRules_Ids) {
        Write-WELog " ASR rules not configured." " INFO"
    }
    else {
        for ($i = 0; $i -le ($WEPrefs.AttackSurfaceReductionRules_Ids.Count - 1); $i++) {
            [PSCustomObject]@{
                RuleId = $WEPrefs.AttackSurfaceReductionRules_Ids[$i]
                Status = Get-AsrStatus -Value $WEPrefs.AttackSurfaceReductionRules_Actions[$i]
            }
        }
    }
}



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================