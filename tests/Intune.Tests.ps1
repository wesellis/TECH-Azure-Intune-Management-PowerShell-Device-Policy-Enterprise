<#
.SYNOPSIS
    Pester tests for Azure Intune management scripts.
.DESCRIPTION
    Comprehensive test suite using Pester v5 for all 411 Intune scripts.
    Tests syntax, functionality, and integration.
#>

BeforeAll {
    $ProjectRoot = Split-Path $PSScriptRoot -Parent
    $ScriptPaths = Get-ChildItem -Path $ProjectRoot -Filter "*.ps1" -Recurse |
        Where-Object { $_.FullName -notmatch '\\tests\\' -and $_.FullName -notmatch '\\\.git\\' }
}

Describe "Script Syntax Validation" {
    Context "PowerShell Syntax" {
        It "Should have valid syntax for <Name>" -ForEach @(
            $ScriptPaths | Select-Object @{N='Name';E={$_.Name}}, @{N='Path';E={$_.FullName}}
        ) {
            $errors = $null
            [System.Management.Automation.Language.Parser]::ParseFile(
                $Path,
                [ref]$null,
                [ref]$errors
            )
            $errors | Should -BeNullOrEmpty
        }
    }
}

Describe "Script Documentation" {
    Context "Comment-Based Help" {
        It "Should have comment-based help in <Name>" -ForEach @(
            $ScriptPaths | Select-Object @{N='Name';E={$_.Name}}, @{N='Path';E={$_.FullName}}
        ) {
            $content = Get-Content $Path -Raw
            $content | Should -Match '<#'
            $content | Should -Match '\.SYNOPSIS'
        }

        It "Should have .DESCRIPTION in <Name>" -ForEach @(
            $ScriptPaths | Select-Object @{N='Name';E={$_.Name}}, @{N='Path';E={$_.FullName}}
        ) {
            $content = Get-Content $Path -Raw
            $content | Should -Match '\.DESCRIPTION'
        }

        It "Should have .EXAMPLE in <Name>" -ForEach @(
            $ScriptPaths | Select-Object @{N='Name';E={$_.Name}}, @{N='Path';E={$_.FullName}}
        ) {
            $content = Get-Content $Path -Raw
            $content | Should -Match '\.EXAMPLE'
        }
    }
}

Describe "Error Handling" {
    Context "Try-Catch Blocks" {
        It "Should use try-catch for error handling in <Name>" -ForEach @(
            $ScriptPaths | Where-Object { (Get-Content $_.FullName -Raw).Length -gt 500 } |
            Select-Object @{N='Name';E={$_.Name}}, @{N='Path';E={$_.FullName}}
        ) {
            $content = Get-Content $Path -Raw
            # Scripts over 500 chars should have error handling
            $content | Should -Match 'try\s*\{'
        }
    }
}

Describe "Security Best Practices" {
    Context "Credential Handling" {
        It "Should not contain hardcoded passwords in <Name>" -ForEach @(
            $ScriptPaths | Select-Object @{N='Name';E={$_.Name}}, @{N='Path';E={$_.FullName}}
        ) {
            $content = Get-Content $Path -Raw
            $content | Should -Not -Match '(password|pwd)\s*=\s*["\'][^"\']+["\']'
        }

        It "Should not use -AsPlainText without -Force in <Name>" -ForEach @(
            $ScriptPaths | Select-Object @{N='Name';E={$_.Name}}, @{N='Path';E={$_.FullName}}
        ) {
            $content = Get-Content $Path -Raw
            if ($content -match 'ConvertTo-SecureString.*-AsPlainText') {
                $content | Should -Match '-Force'
            }
        }
    }

    Context "Dangerous Commands" {
        It "Should not use Invoke-Expression in <Name>" -ForEach @(
            $ScriptPaths | Select-Object @{N='Name';E={$_.Name}}, @{N='Path';E={$_.FullName}}
        ) {
            $content = Get-Content $Path -Raw
            $content | Should -Not -Match 'Invoke-Expression|iex\s'
        }
    }
}

Describe "Code Quality" {
    Context "Line Length" {
        It "Should not have excessive line lengths in <Name>" -ForEach @(
            $ScriptPaths | Select-Object @{N='Name';E={$_.Name}}, @{N='Path';E={$_.FullName}}
        ) {
            $lines = Get-Content $Path
            $longLines = $lines | Where-Object { $_.Length -gt 150 }
            $longLines.Count | Should -BeLessThan ($lines.Count * 0.1) # Less than 10% long lines
        }
    }
}

Describe "Module Dependencies" {
    Context "Required Modules" {
        It "Should check for Microsoft.Graph.Intune availability" {
            $module = Get-Module -ListAvailable -Name Microsoft.Graph.Intune
            $module | Should -Not -BeNullOrEmpty
        }

        It "Should check for AzureAD availability" {
            $module = Get-Module -ListAvailable -Name AzureAD
            $module | Should -Not -BeNullOrEmpty
        }
    }
}

Describe "Intune-Specific Tests" {
    Context "Graph API Integration" {
        It "Should use proper Graph API endpoints in <Name>" -ForEach @(
            $ScriptPaths | Where-Object { (Get-Content $_.FullName -Raw) -match 'graph\.microsoft' } |
            Select-Object @{N='Name';E={$_.Name}}, @{N='Path';E={$_.FullName}}
        ) {
            $content = Get-Content $Path -Raw
            # Check for proper v1.0 or beta endpoint usage
            $content | Should -Match 'graph\.microsoft\.com/(v1\.0|beta)/'
        }
    }

    Context "Authentication" {
        It "Should handle authentication in <Name>" -ForEach @(
            $ScriptPaths | Where-Object { (Get-Content $_.FullName -Raw) -match 'Connect-' } |
            Select-Object @{N='Name';E={$_.Name}}, @{N='Path';E={$_.FullName}}
        ) {
            $content = Get-Content $Path -Raw
            # Should have authentication handling
            ($content -match 'Connect-MgGraph' -or
             $content -match 'Connect-AzureAD' -or
             $content -match 'Get-MgContext') | Should -BeTrue
        }
    }
}

Describe "File Organization" {
    Context "Directory Structure" {
        It "Should have Intune directory" {
            Test-Path "$ProjectRoot\Intune" | Should -BeTrue
        }

        It "Should have Device-Management subdirectory" {
            Test-Path "$ProjectRoot\Intune\Device-Management" | Should -BeTrue
        }

        It "Should have PowerShell-Scripts subdirectory" {
            Test-Path "$ProjectRoot\Intune\PowerShell-Scripts" | Should -BeTrue
        }

        It "Should have tests directory" {
            Test-Path "$ProjectRoot\tests" | Should -BeTrue
        }
    }
}

Describe "Documentation Files" {
    Context "Required Documentation" {
        It "Should have README.md" {
            Test-Path "$ProjectRoot\README.md" | Should -BeTrue
        }

        It "Should have LICENSE" {
            Test-Path "$ProjectRoot\LICENSE" | Should -BeTrue
        }

        It "Should have SECURITY.md" {
            Test-Path "$ProjectRoot\SECURITY.md" | Should -BeTrue
        }

        It "Should have CONTRIBUTING.md" {
            Test-Path "$ProjectRoot\CONTRIBUTING.md" | Should -BeTrue
        }
    }
}
