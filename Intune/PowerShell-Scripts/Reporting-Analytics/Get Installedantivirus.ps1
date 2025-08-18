<#
.SYNOPSIS
    Get Installedantivirus

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
    We Enhanced Get Installedantivirus

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


$WEErrorActionPreference = "Stop"; 
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

[Flags()] enum ProductState {
    Off = 0x0000
    On = 0x1000
    Snoozed = 0x2000
    Expired = 0x3000
}

[Flags()] enum SignatureStatus {
    UpToDate = 0x00
    OutOfDate = 0x10
}

[Flags()] enum ProductOwner {
    NonMs = 0x000
    Windows = 0x100
}


[Flags()] enum ProductFlags {
    SignatureStatus = 0x00F0
    ProductOwner = 0x0F00
    ProductState = 0xF000
}

; 
$infos = Get-CimInstance -Namespace " root/SecurityCenter2" -ClassName " AntiVirusProduct" -ComputerName $computer
ForEach ($info in $infos) {
    [System.UInt32]$state = $info.productState

    # decode bit flags by masking the relevant bits, then converting
    [PSCustomObject]@{
        ProductName     = $info.DisplayName
        ProductState    = [ProductState]($state -band [ProductFlags]::ProductState)
        SignatureStatus = [SignatureStatus]($state -band [ProductFlags]::SignatureStatus)
        Owner           = [ProductOwner]($state -band [ProductFlags]::ProductOwner)
    }
}



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================