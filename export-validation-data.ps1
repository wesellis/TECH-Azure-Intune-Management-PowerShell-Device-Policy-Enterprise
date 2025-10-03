$reports = .\tests\Invoke-ScriptValidation.ps1 -Path ".\Intune"

$export = $reports | Select-Object `
    Name, `
    OverallScore, `
    @{N='SyntaxValid';E={$_.Syntax.Valid}}, `
    @{N='SyntaxErrors';E={$_.Syntax.Errors.Count}}, `
    @{N='DocScore';E={$_.Documentation.Score}}, `
    @{N='MissingSections';E={$_.Documentation.MissingSections -join ', '}}, `
    @{N='SecurityScore';E={$_.Security.Score}}, `
    @{N='SecurityIssues';E={$_.Security.Issues -join '; '}}, `
    @{N='ErrorHandlingScore';E={$_.ErrorHandling.Score}}, `
    @{N='CodeQualityScore';E={$_.CodeQuality.Score}}, `
    Path | Sort-Object Name

$export | Export-Csv -Path "intune-script-analysis.csv" -NoTypeInformation
Write-Host "✓ Exported $($export.Count) scripts to intune-script-analysis.csv"
