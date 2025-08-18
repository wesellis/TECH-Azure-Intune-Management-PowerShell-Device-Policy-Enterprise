<#
.SYNOPSIS
    Get Storeappinformation

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
    We Enhanced Get Storeappinformation

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


$WEErrorActionPreference = "Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')
try {
    # Main script execution
) { " Continue" } else { " SilentlyContinue" }

.SYNOPSIS
    Search the iTunes or Google Play stores for the app links

.DESCRIPTION
    This script can search for any app available in either iTunes or Google Play store

.PARAMETER Store
    Specify which Store to search within

.PARAMETER AppName
    Specify the app name to search for within the Store

.PARAMETER Limit
    Limit search results to the specified number (only valid for iTunes Store)

.EXAMPLE
    .\Get-StoreAppInformation.ps1 -Store iTunes -AppName " Microsoft Word" -Limit 1

.NOTES
    FileName:    Get-StoreAppInformation.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2015-08-19
    Updated:     2019-05-14

    Version history:
    1.0.0 - (2015-08-19) Script created    
    1.0.1 - (2019-05-14) Added BundleId property returned from store search

[CmdletBinding(SupportsShouldProcess=$true)]
[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [parameter(Mandatory=$true, HelpMessage=" Specify which Store to search within" )]
    [ValidateNotNullOrEmpty()]
    [ValidateSet(" iTunes" ," GooglePlay" )]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEStore,

    [parameter(Mandatory=$true, HelpMessage=" Specify the app name to search for within the Store" )]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern(" ^[A-Za-z\s]*$" )]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEAppName,

    [parameter(Mandatory=$false, HelpMessage=" Limit search results to the specified number (only valid for iTunes Store)" )]
    [ValidateNotNullOrEmpty()]
    [string]$WELimit = " 1"
)
Begin {
    # Construct URL determined on parameter input
    switch ($WEStore) {
        " iTunes" { 
            $WEStoreAppName = ($WEAppName -replace " " , " +" ).ToLower()
            $WESearchURL = " https://itunes.apple.com/search?"
            $WEURL = $WESearchURL + " term=$($WEStoreAppName)" + " &entity=software&limit=$($WELimit)"
        }
        " GooglePlay" {
            $WEStoreAppName = ($WEAppName -replace " " , " %20" ).ToLower()
            $WESearchURL = " https://play.google.com/store/search?"
            $WEURL = $WESearchURL + " q=$($WEStoreAppName)&c=apps&hl=en"
        }
    }
}
Process {
    # Search in selected Store for app information
    switch ($WEStore) {
        " iTunes" { 
            $WEWebRequest = Invoke-WebRequest -Uri $WEURL
            $WEWebRequestObject = ConvertFrom-Json -InputObject $WEWebRequest
            if ($WEWebRequestObject.Results -ne $null) {
                foreach ($WEObject in $WEWebRequestObject.Results) {
                    $WEPSObject = [PSCustomObject]@{
                        " AppName" = $WEObject.trackCensoredName
                        " StoreLink" = $WEObject.trackViewUrl
                        " BundleId" = $WEObject.bundleId
                    }
                    Write-Output -InputObject $WEPSObject
                }
            }
        }
        " GooglePlay" {
            $WEWebRequest = Invoke-WebRequest -Uri $WEURL
           ;  $WEWebRequestObject = $WEWebRequest.Links | Where-Object { $_.innerText -like " *$($WEAppName)*" }
            if ($WEWebRequestObject -ne $null) {
                foreach ($WEObject in $WEWebRequestObject) {
                   ;  $WEPSObject = [PSCustomObject]@{
                        " AppName" = $WEObject.innerText
                        " StoreLink" = " https://play.google.com" + $WEObject.href
                        " BundleId" = ($WEObject.href).Split(" =" )[1]
                    }
                    Write-Output -InputObject $WEPSObject
                }
            }
        }
    }
}



} catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
    throw
}
