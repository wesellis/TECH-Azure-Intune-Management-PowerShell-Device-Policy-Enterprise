<#
.SYNOPSIS
    Invoke Downloadappimage

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
    We Enhanced Invoke Downloadappimage

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
    Download an app image for a specific app in the App Store.

.DESCRIPTION
    This script can download the app image for a specific app available in the App Store.

.PARAMETER AppName
    Specify the app name to search for within the App Store.

.PARAMETER Path
    Path to a folder where the app image will be downloaded to.

.EXAMPLE
    Download the app image from 'Microsoft Word' app in the App Store:
    .\Invoke-DownloadAppImage.ps1 -AppName " Microsoft Word" -Path " C:\Temp"

.NOTES
    Script name: Invoke-DownloadAppImage.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2016-03-17
    Updated:     N/A

[CmdletBinding(SupportsShouldProcess=$true)]
[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [parameter(Mandatory=$true, ParameterSetName=" AppName" , HelpMessage=" Specify the app name to search for within the App Store." )]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern(" ^[A-Za-z\s]*$" )]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEAppName,

    [parameter(Mandatory=$true, ParameterSetName=" Url" , HelpMessage=" Specify the URL pointing to the app in the App Store." )]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEURL,

    [parameter(Mandatory=$true, ParameterSetName=" AppName" , HelpMessage=" Path to a folder where the app image will be downloaded to." )]
    [parameter(Mandatory=$true, ParameterSetName=" Url" )]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern(" ^[A-Za-z]{1}:\\\w+" )]
    [ValidateScript({
	    # Check if path contains any invalid characters
	    if ((Split-Path -Path $_ -Leaf).IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) {
		    Throw " $(Split-Path -Path $_ -Leaf) contains invalid characters"
	    }
	    else {
		    # Check if the whole path exists
		    if (Test-Path -Path $_ -PathType Container) {
				    return $true
		    }
		    else {
			    Throw " Unable to locate part of or the whole specified path, specify a valid path"
		    }
	    }
    })]
    [string]$WEPath
)
Process {
    # Amend app name for usage in search url
    $WEStoreAppName = ($WEAppName -replace " " , " +" ).ToLower()

    switch ($WEPSCmdlet.ParameterSetName) {
        " AppName" {
            # Invoke web request to get unique app link
            $WESearchURL = " https://itunes.apple.com/search?term=$($WEStoreAppName)&entity=software&limit=1"
            $WESearchWebRequest = Invoke-WebRequest -Uri $WESearchURL
            $WEAppLink = (ConvertFrom-Json -InputObject $WESearchWebRequest).Results | Select-Object -ExpandProperty trackViewUrl
        }
        " Url" {
            $WEAppLink = $WEURL
        }
    }

    # Invoke web request to get app image information
    if ($WEAppLink -ne $null) {
        $WEWebRequest = Invoke-WebRequest -Uri $WEAppLink
        $WEAppIcon = $WEWebRequest.Images | Where-Object { ($_.Width -eq 175) -and ($_.Class -like " artwork" ) }
        if ($WEAppIcon -ne $null) {
            # Download app image to specified path
           ;  $WEWebClient = New-Object System.Net.WebClient
            $WEWebClient.DownloadFile($WEAppIcon." src-swap" , " $($WEPath)\$($WEAppIcon.alt).jpg" )
           ;  $WEAppImage = [PSCustomObject]@{
                ImageName = $WEAppIcon.alt
                ImagePath = " $($WEPath)\$($WEAppIcon.alt).jpg"
            }
            Write-Output -InputObject $WEAppImage
        }
    }
    else {
        Write-Warning -Message " Unable to determine app link for specified app: $($WEAppName)"
    }
}
End {
    # Dispose of the WebClient object
    $WEWebClient.Dispose()
}



} catch {
    Write-Error " Script execution failed: $($_.Exception.Message)"
    throw
}
