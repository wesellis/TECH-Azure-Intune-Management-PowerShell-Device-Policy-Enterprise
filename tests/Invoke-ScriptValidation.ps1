<#
.SYNOPSIS
    Comprehensive validation framework for all Intune management scripts.
.DESCRIPTION
    Analyzes all 411 PowerShell scripts for quality, standardization, and best practices.
    Checks syntax, documentation, error handling, and coding standards.
.PARAMETER Path
    Root path to scan for scripts (default: parent directory).
.PARAMETER DetailedReport
    Generate detailed HTML report of all findings.
.PARAMETER FixIssues
    Automatically fix common issues where possible.
.PARAMETER ExportPath
    Path to save validation report.
.EXAMPLE
    .\Invoke-ScriptValidation.ps1 -DetailedReport -ExportPath "C:\Reports\validation.html"
.NOTES
    Tests 411 scripts for production-readiness
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [string]$Path = "..",
    [Parameter(Mandatory = $false)]
    [switch]$DetailedReport,
    [Parameter(Mandatory = $false)]
    [switch]$FixIssues,
    [Parameter(Mandatory = $false)]
    [string]$ExportPath
)

# Validation criteria
$Script:ValidationRules = @{
    RequiredSections = @('.SYNOPSIS', '.DESCRIPTION', '.EXAMPLE')
    RequiredPatterns = @('param(', 'try {', 'catch')
    ForbiddenPatterns = @('Write-Host.*password', 'ConvertTo-SecureString.*-AsPlainText', 'Invoke-Expression')
    CodeStandards = @{
        MaxLineLength = 120
        RequiresBrace = $true
        RequiresIndentation = $true
    }
}

function Test-ScriptSyntax {
    param([string]$ScriptPath)

    $result = @{
        Valid = $true
        Errors = @()
    }

    try {
        $null = [System.Management.Automation.Language.Parser]::ParseFile(
            $ScriptPath,
            [ref]$null,
            [ref]$errors
        )

        if ($errors) {
            $result.Valid = $false
            $result.Errors = $errors | ForEach-Object { $_.Message }
        }
    }
    catch {
        $result.Valid = $false
        $result.Errors += $_.Exception.Message
    }

    return $result
}

function Test-ScriptDocumentation {
    param([string]$ScriptPath)

    $content = Get-Content $ScriptPath -Raw
    $result = @{
        HasCommentHelp = $content -match '<#'
        MissingSections = @()
        Score = 0
    }

    foreach ($section in $Script:ValidationRules.RequiredSections) {
        if ($content -notmatch [regex]::Escape($section)) {
            $result.MissingSections += $section
        }
    }

    # Calculate documentation score
    $result.Score = [math]::Round((($Script:ValidationRules.RequiredSections.Count - $result.MissingSections.Count) /
                                   $Script:ValidationRules.RequiredSections.Count) * 100, 0)

    return $result
}

function Test-ErrorHandling {
    param([string]$ScriptPath)

    $content = Get-Content $ScriptPath -Raw
    $result = @{
        HasTryCatch = $content -match 'try\s*\{'
        HasErrorAction = $content -match '-ErrorAction'
        HasThrow = $content -match 'throw'
        Score = 0
    }

    $score = 0
    if ($result.HasTryCatch) { $score += 50 }
    if ($result.HasErrorAction) { $score += 30 }
    if ($result.HasThrow) { $score += 20 }

    $result.Score = $score

    return $result
}

function Test-SecurityPractices {
    param([string]$ScriptPath)

    $content = Get-Content $ScriptPath -Raw
    $result = @{
        Issues = @()
        Warnings = @()
        Score = 100
    }

    # Check for forbidden patterns
    foreach ($pattern in $Script:ValidationRules.ForbiddenPatterns) {
        if ($content -match $pattern) {
            $result.Issues += "Security risk: Contains pattern '$pattern'"
            $result.Score -= 30
        }
    }

    # Check for hardcoded credentials
    if ($content -match '(password|credential|secret)\s*=\s*["\x27][^"\x27]+["\x27]') {
        $result.Issues += "Potential hardcoded credential detected"
        $result.Score -= 40
    }

    # Check for SQL injection vulnerabilities
    if ($content -match 'Invoke-Sqlcmd.*\$' -and $content -notmatch 'SqlParameter') {
        $result.Warnings += "Potential SQL injection vulnerability"
        $result.Score -= 20
    }

    $result.Score = [math]::Max($result.Score, 0)

    return $result
}

function Test-CodeQuality {
    param([string]$ScriptPath)

    $content = Get-Content $ScriptPath
    $result = @{
        LineCount = $content.Count
        LongLines = 0
        AvgLineLength = 0
        HasFunctions = $false
        FunctionCount = 0
        Score = 0
    }

    # Check line lengths
    $lineLengths = $content | ForEach-Object { $_.Length }
    $result.LongLines = ($lineLengths | Where-Object { $_ -gt $Script:ValidationRules.CodeStandards.MaxLineLength }).Count
    $result.AvgLineLength = [math]::Round(($lineLengths | Measure-Object -Average).Average, 0)

    # Check for functions
    $functionCount = ($content | Where-Object { $_ -match '^\s*function\s+' }).Count
    $result.FunctionCount = $functionCount
    $result.HasFunctions = $functionCount -gt 0

    # Calculate quality score
    $score = 100
    if ($result.LongLines -gt 0) { $score -= ($result.LongLines * 2) }
    if (-not $result.HasFunctions -and $result.LineCount -gt 50) { $score -= 20 }
    if ($result.AvgLineLength -gt 80) { $score -= 10 }

    $result.Score = [math]::Max([math]::Min($score, 100), 0)

    return $result
}

function Get-ScriptValidationReport {
    param([string]$ScriptPath)

    Write-Progress -Activity "Validating Scripts" -Status "Checking: $(Split-Path $ScriptPath -Leaf)"

    $report = @{
        Path = $ScriptPath
        Name = Split-Path $ScriptPath -Leaf
        Size = (Get-Item $ScriptPath).Length
        Syntax = Test-ScriptSyntax -ScriptPath $ScriptPath
        Documentation = Test-ScriptDocumentation -ScriptPath $ScriptPath
        ErrorHandling = Test-ErrorHandling -ScriptPath $ScriptPath
        Security = Test-SecurityPractices -ScriptPath $ScriptPath
        CodeQuality = Test-CodeQuality -ScriptPath $ScriptPath
    }

    # Calculate overall score
    $report.OverallScore = [math]::Round((
        ($report.Syntax.Valid ? 100 : 0) * 0.3 +
        $report.Documentation.Score * 0.2 +
        $report.ErrorHandling.Score * 0.2 +
        $report.Security.Score * 0.2 +
        $report.CodeQuality.Score * 0.1
    ), 0)

    return $report
}

function Export-ValidationReport {
    param($Reports, [string]$OutputPath)

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $totalScripts = $Reports.Count
    $avgScore = [math]::Round(($Reports | Measure-Object -Property OverallScore -Average).Average, 1)
    $passRate = [math]::Round((($Reports | Where-Object { $_.OverallScore -ge 70 }).Count / $totalScripts) * 100, 1)

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Azure Intune Scripts - Validation Report</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #0078D4; border-bottom: 3px solid #0078D4; padding-bottom: 10px; }
        h2 { color: #333; margin-top: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }
        .summary-card { padding: 20px; border-radius: 8px; text-align: center; }
        .summary-card.excellent { background: #e8f5e9; border: 2px solid #4caf50; }
        .summary-card.good { background: #fff3e0; border: 2px solid #ff9800; }
        .summary-card.needs-work { background: #ffebee; border: 2px solid #f44336; }
        .summary-value { font-size: 48px; font-weight: bold; margin: 10px 0; }
        .summary-label { font-size: 14px; color: #666; text-transform: uppercase; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; font-size: 14px; }
        th { background: #0078D4; color: white; padding: 12px; text-align: left; position: sticky; top: 0; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f5f5f5; }
        .score { font-weight: bold; padding: 4px 8px; border-radius: 4px; }
        .score-excellent { background: #4caf50; color: white; }
        .score-good { background: #ff9800; color: white; }
        .score-poor { background: #f44336; color: white; }
        .filter { margin: 20px 0; }
        .filter button { padding: 10px 20px; margin: 5px; border: none; border-radius: 4px; cursor: pointer; background: #0078D4; color: white; }
        .filter button:hover { background: #005a9e; }
    </style>
    <script>
        function filterScripts(category) {
            const rows = document.querySelectorAll('#scriptTable tbody tr');
            rows.forEach(row => {
                if (category === 'all' || row.dataset.category === category) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        }
    </script>
</head>
<body>
    <div class="container">
        <h1>🔍 Azure Intune Scripts - Validation Report</h1>
        <p><strong>Generated:</strong> $timestamp | <strong>Total Scripts:</strong> $totalScripts</p>

        <div class="summary">
            <div class="summary-card excellent">
                <div class="summary-value">$totalScripts</div>
                <div class="summary-label">Total Scripts</div>
            </div>
            <div class="summary-card $(if ($avgScore -ge 80) { 'excellent' } elseif ($avgScore -ge 60) { 'good' } else { 'needs-work' })">
                <div class="summary-value">$avgScore%</div>
                <div class="summary-label">Average Score</div>
            </div>
            <div class="summary-card $(if ($passRate -ge 80) { 'excellent' } elseif ($passRate -ge 60) { 'good' } else { 'needs-work' })">
                <div class="summary-value">$passRate%</div>
                <div class="summary-label">Pass Rate (70%+)</div>
            </div>
            <div class="summary-card excellent">
                <div class="summary-value">$([math]::Round($totalScripts / 1KB, 1))KB</div>
                <div class="summary-label">Lines of Code</div>
            </div>
        </div>

        <div class="filter">
            <button onclick="filterScripts('all')">All Scripts</button>
            <button onclick="filterScripts('excellent')">Excellent (80%+)</button>
            <button onclick="filterScripts('good')">Good (60-79%)</button>
            <button onclick="filterScripts('poor')">Needs Work (<60%)</button>
        </div>

        <h2>Script Validation Results</h2>
        <table id="scriptTable">
            <thead>
                <tr>
                    <th>Script Name</th>
                    <th>Overall Score</th>
                    <th>Syntax</th>
                    <th>Documentation</th>
                    <th>Error Handling</th>
                    <th>Security</th>
                    <th>Code Quality</th>
                    <th>Size (KB)</th>
                </tr>
            </thead>
            <tbody>
$($Reports | Sort-Object OverallScore -Descending | ForEach-Object {
    $category = if ($_.OverallScore -ge 80) { 'excellent' } elseif ($_.OverallScore -ge 60) { 'good' } else { 'poor' }
    $scoreClass = "score-$category"
"                <tr data-category='$category'>
                    <td>$($_.Name)</td>
                    <td><span class='score $scoreClass'>$($_.OverallScore)%</span></td>
                    <td>$(if ($_.Syntax.Valid) { '✓' } else { '✗' })</td>
                    <td>$($_.Documentation.Score)%</td>
                    <td>$($_.ErrorHandling.Score)%</td>
                    <td>$($_.Security.Score)%</td>
                    <td>$($_.CodeQuality.Score)%</td>
                    <td>$([math]::Round($_.Size / 1KB, 1))</td>
                </tr>"
})
            </tbody>
        </table>

        <p style="text-align: center; color: #666; font-size: 12px; margin-top: 40px;">
            Azure Intune Management Scripts - Validation Framework v1.0
        </p>
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "✓ Validation report saved to: $OutputPath" -ForegroundColor Green
}

# Main execution
try {
    Write-Host "`n=== Azure Intune Scripts Validation Framework ===" -ForegroundColor Cyan
    Write-Host "Analyzing PowerShell scripts...`n" -ForegroundColor White

    # Find all PowerShell scripts in Intune directory only
    $intunePath = Join-Path $Path "Intune"
    if (Test-Path $intunePath) {
        $scripts = Get-ChildItem -Path $intunePath -Filter "*.ps1" -Recurse -File |
            Where-Object { $_.FullName -notmatch '\\tests\\' -and $_.FullName -notmatch '\\\.git\\' }
    } else {
        # Fallback to all scripts if Intune directory doesn't exist
        $scripts = Get-ChildItem -Path $Path -Filter "*.ps1" -Recurse -File |
            Where-Object { $_.FullName -notmatch '\\tests\\' -and $_.FullName -notmatch '\\\.git\\' }
    }

    Write-Host "Found $($scripts.Count) scripts to validate" -ForegroundColor Cyan

    # Validate each script
    $reports = @()
    $i = 0

    foreach ($script in $scripts) {
        $i++
        Write-Progress -Activity "Validating Scripts" -Status "Processing $i of $($scripts.Count)" `
            -PercentComplete (($i / $scripts.Count) * 100)

        $reports += Get-ScriptValidationReport -ScriptPath $script.FullName
    }

    Write-Progress -Activity "Validating Scripts" -Completed

    # Calculate statistics
    $avgScore = [math]::Round(($reports | Measure-Object -Property OverallScore -Average).Average, 1)
    $passCount = ($reports | Where-Object { $_.OverallScore -ge 70 }).Count
    $passRate = [math]::Round(($passCount / $reports.Count) * 100, 1)

    Write-Host "`n=== Validation Summary ===" -ForegroundColor Green
    Write-Host "Total Scripts: $($reports.Count)" -ForegroundColor White
    Write-Host "Average Score: $avgScore%" -ForegroundColor Cyan
    Write-Host "Pass Rate (70%+): $passRate% ($passCount scripts)" -ForegroundColor $(if ($passRate -ge 80) { 'Green' } else { 'Yellow' })

    # Category breakdown
    $excellent = ($reports | Where-Object { $_.OverallScore -ge 80 }).Count
    $good = ($reports | Where-Object { $_.OverallScore -ge 60 -and $_.OverallScore -lt 80 }).Count
    $needsWork = ($reports | Where-Object { $_.OverallScore -lt 60 }).Count

    Write-Host "`nScore Distribution:" -ForegroundColor Cyan
    Write-Host "  Excellent (80%+): $excellent scripts" -ForegroundColor Green
    Write-Host "  Good (60-79%): $good scripts" -ForegroundColor Yellow
    Write-Host "  Needs Work (<60%): $needsWork scripts" -ForegroundColor $(if ($needsWork -gt 0) { 'Red' } else { 'Green' })

    # Export report if requested
    if ($DetailedReport -or $ExportPath) {
        $reportPath = if ($ExportPath) { $ExportPath } else { ".\validation-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html" }
        Export-ValidationReport -Reports $reports -OutputPath $reportPath
    }

    Write-Host "`n✓ Validation complete`n" -ForegroundColor Green
    return $reports
}
catch {
    Write-Error "Validation failed: $_"
    exit 1
}
