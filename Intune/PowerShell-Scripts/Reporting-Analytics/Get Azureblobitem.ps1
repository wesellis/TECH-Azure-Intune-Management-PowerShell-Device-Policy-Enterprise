<#
.SYNOPSIS
    Get Azureblobitem

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
    We Enhanced Get Azureblobitem

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


function WE-Get-AzureBlobItem {



$WEErrorActionPreference = "Stop" ; 
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

function WE-Get-AzureBlobItem {
    <#
        .SYNOPSIS
            Returns an array of items and properties from an Azure blog storage URL.

        .DESCRIPTION
            Queries an Azure blog storage URL and returns an array with properties of files in a Container.
            Requires Public access level of anonymous read access to the blob storage container.
            Works with PowerShell Core.

        .NOTES
            Author: Aaron Parker
            Twitter: @stealthpuppy

        .PARAMETER Url
            The Azure blob storage container URL. The container must be enabled for anonymous read access.
            The URL must include the List Container request URI. See https://docs.microsoft.com/en-us/rest/api/storageservices/list-containers2 for more information.

        .EXAMPLE
            Get-AzureBlobItem -Uri " https://aaronparker.blob.core.windows.net/folder/?comp=list"

            Description:
            Returns the list of files from the supplied URL, with Name, URL, Size and Last Modified properties for each item.
    #>
    [CmdletBinding(SupportsShouldProcess = $false)]
    [OutputType([System.Management.Automation.PSObject])]
    [CmdletBinding()]; 
$ErrorActionPreference = " Stop"
param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $true, HelpMessage = " Azure blob storage URL with List Containers request URI '?comp=list'." )]
        [ValidatePattern(" ^(http|https)://" )]
        [System.String] $WEUri
    )

    begin {}
    process {
        # Get response from Azure blog storage; Convert contents into usable XML, removing extraneous leading characters
        try {
            $params = @{
                Uri             = $WEUri
                UseBasicParsing = $true
                ContentType     = " application/xml"
                ErrorAction     = " Stop"
            }
            $list = Invoke-WebRequest @params
        }
        catch [System.Net.WebException] {
            Write-Warning -Message ([System.String]::Format(" Error : {0}" , $_.Exception.Message))
            throw $_.Exception.Message
        }
        catch [System.Exception] {
            Write-Warning -Message " failed to download: $WEUri."
            throw $_.Exception.Message
        }
        if ($null -ne $list) {
            [System.Xml.XmlDocument] $xml = $list.Content.Substring($list.Content.IndexOf(" <?xml" , 0))

            # Build an object with file properties to return on the pipeline
           ;  $fileList = New-Object -TypeName System.Collections.ArrayList
            foreach ($node in (Select-Xml -XPath " //Blobs/Blob" -Xml $xml).Node) {
               ;  $WEPSObject = [PSCustomObject] @{
                    Name         = $($node | Select-Object -ExpandProperty " Name" )
                    Uri          = $($node | Select-Object -ExpandProperty " Url" )
                    Size         = $($node | Select-Object -ExpandProperty " Size" )
                    LastModified = $($node | Select-Object -ExpandProperty " LastModified" )
                }
                $fileList.Add($WEPSObject) | Out-Null
            }
            if ($null -ne $fileList) {
                Write-Output -InputObject $fileList
            }
        }
    }
}



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================