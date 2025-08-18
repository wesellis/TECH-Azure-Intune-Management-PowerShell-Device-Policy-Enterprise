<#
.SYNOPSIS
    Azure Security Center Compliance Scanner

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
    We Enhanced Azure Security Center Compliance Scanner

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

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Parameter(Mandatory=$false)]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WESubscriptionId,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet(" All" , " CIS" , " PCI" , " SOC2" , " ISO27001" , " NIST" )]
    [string]$WEComplianceStandard = " All" ,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet(" All" , " High" , " Medium" , " Low" )]
    [string]$WEMinimumSeverity = " Medium" ,
    
    [Parameter(Mandatory=$false)]
    [switch]$WEExportReport,
    
    [Parameter(Mandatory=$false)]
    [string]$WEOutputPath = " .\security-compliance-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
)


Import-Module (Join-Path $WEPSScriptRoot " ..\modules\AzureAutomationCommon\AzureAutomationCommon.psm1" ) -Force

Show-Banner -ScriptName " Azure Security Center Compliance Scanner" -Version " 1.0" -Description " Comprehensive security compliance assessment and reporting"

try {
    Write-ProgressStep -StepNumber 1 -TotalSteps 5 -StepName " Security Connection" -Status " Validating security modules"
    if (-not (Test-AzureConnection -RequiredModules @('Az.Security', 'Az.PolicyInsights'))) {
        throw " Security modules validation failed"
    }

    if ($WESubscriptionId) {
        Set-AzContext -SubscriptionId $WESubscriptionId
    }

    Write-ProgressStep -StepNumber 2 -TotalSteps 5 -StepName " Compliance Assessment" -Status " Gathering compliance data"
    
    # Get security assessments
    $assessments = Get-AzSecurityAssessment -ErrorAction Stop
    
    # Get policy compliance
    $policyStates = Get-AzPolicyState -ErrorAction Stop
    
    # Get security score
    $securityScore = Get-AzSecurityScore -ErrorAction Stop

    Write-ProgressStep -StepNumber 3 -TotalSteps 5 -StepName " Analysis" -Status " Analyzing compliance status"
    
   ;  $complianceReport = @{
        SubscriptionId = (Get-AzContext).Subscription.Id
        SubscriptionName = (Get-AzContext).Subscription.Name
        AssessmentDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        SecurityScore = $securityScore
        TotalAssessments = $assessments.Count
        FailedAssessments = ($assessments | Where-Object { $_.Status.Code -eq " Unhealthy" }).Count
        ComplianceRate = [math]::Round((($assessments.Count - ($assessments | Where-Object { $_.Status.Code -eq " Unhealthy" }).Count) / $assessments.Count) * 100, 2)
        Assessments = $assessments | ForEach-Object {
            @{
                Name = $_.DisplayName
                Status = $_.Status.Code
                Severity = $_.Metadata.Severity
                Category = $_.Metadata.Categories
                Description = $_.Status.Description
                RemediationDescription = $_.Metadata.RemediationDescription
            }
        }
        PolicyCompliance = @{
            TotalPolicies = $policyStates.Count
            NonCompliant = ($policyStates | Where-Object { $_.ComplianceState -eq " NonCompliant" }).Count
            Policies = $policyStates | Group-Object PolicyDefinitionName | ForEach-Object {
                @{
                    PolicyName = $_.Name
                    TotalResources = $_.Count
                    NonCompliantResources = ($_.Group | Where-Object { $_.ComplianceState -eq " NonCompliant" }).Count
                    ComplianceRate = [math]::Round((($_.Count - ($_.Group | Where-Object { $_.ComplianceState -eq " NonCompliant" }).Count) / $_.Count) * 100, 2)
                }
            }
        }
    }

    Write-ProgressStep -StepNumber 4 -TotalSteps 5 -StepName " Report Generation" -Status " Generating compliance report"
    
    if ($WEExportReport) {
        $complianceReport | ConvertTo-Json -Depth 10 | Out-File -FilePath $WEOutputPath -Encoding UTF8
        Write-Log " ✓ Compliance report exported to: $WEOutputPath" -Level SUCCESS
    }

    Write-ProgressStep -StepNumber 5 -TotalSteps 5 -StepName " Summary" -Status " Displaying results"

    # Display summary
    Write-WELog "" " INFO"
    Write-WELog " ════════════════════════════════════════════════════════════════════════════════════════════" " INFO" -ForegroundColor Green
    Write-WELog "                              SECURITY COMPLIANCE REPORT" " INFO" -ForegroundColor Green  
    Write-WELog " ════════════════════════════════════════════════════════════════════════════════════════════" " INFO" -ForegroundColor Green
    Write-WELog "" " INFO"
    Write-WELog " 🛡️ Security Score: $($complianceReport.SecurityScore.SecureScorePercentage)%" " INFO" -ForegroundColor Cyan
    Write-WELog " 📊 Compliance Rate: $($complianceReport.ComplianceRate)%" " INFO" -ForegroundColor Green
    Write-WELog " ❌ Failed Assessments: $($complianceReport.FailedAssessments)/$($complianceReport.TotalAssessments)" " INFO" -ForegroundColor Yellow
    
    Write-WELog "" " INFO"
    Write-WELog " 🚨 High Priority Issues:" " INFO" -ForegroundColor Red
   ;  $highPriorityIssues = $complianceReport.Assessments | Where-Object { $_.Status -eq " Unhealthy" -and $_.Severity -eq " High" }
    if ($highPriorityIssues.Count -gt 0) {
        $highPriorityIssues | ForEach-Object {
            Write-WELog "   • $($_.Name)" " INFO" -ForegroundColor White
        }
    } else {
        Write-WELog "   • No high priority issues found" " INFO" -ForegroundColor Green
    }
    
    Write-WELog "" " INFO"

    Write-Log " ✅ Security compliance scan completed successfully!" -Level SUCCESS

} catch {
    Write-Log " ❌ Security compliance scan failed: $($_.Exception.Message)" -Level ERROR -Exception $_.Exception
    exit 1
}

Write-Progress -Activity " Security Compliance Scan" -Completed


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================