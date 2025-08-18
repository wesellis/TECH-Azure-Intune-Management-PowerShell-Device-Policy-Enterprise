<#
.SYNOPSIS
    Get Azureaddevicerecordsbyserialnumber

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
    We Enhanced Get Azureaddevicerecordsbyserialnumber

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
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

.SYNOPSIS
    Get a list of Azure AD device records that matches the hardware identifier of the associated Azure AD device 
    object of a device identity in Windows Autopilot based on the serial number as input.

.DESCRIPTION
    This script will retrieve all Azure AD device records that matches the hardware identifier of the associated Azure AD device 
    object of a device identity in Windows Autopilot based on the serial number as input

.PARAMETER TenantID
    Specify the Azure AD tenant ID.

.PARAMETER ClientID
    Specify the service principal, also known as app registration, Client ID (also known as Application ID).

.PARAMETER SerialNumber
    Specify the serial number of a device known to Windows Autopilot.

.EXAMPLE
    # Retrieve a list of associated Azure AD device records based on hardware identifier by specifying a known serial number in Windows Autopilot:
    .\Get-AzureADDeviceRecordsBySerialNumber.ps1 -TenantID " <tenant_id>" -ClientID " <client_id>" -SerialNumber " 1234567"

.NOTES
    FileName:    Get-AzureADDeviceRecordsBySerialNumber.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2021-03-22
    Updated:     2021-03-22

    Version history:
    1.0.0 - (2021-03-22) Script created

[CmdletBinding(SupportsShouldProcess = $true)]
[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [parameter(Mandatory = $true, HelpMessage = " Specify the Azure AD tenant ID." )]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WETenantID,

    [parameter(Mandatory = $true, HelpMessage = " Specify the service principal, also known as app registration, Client ID (also known as Application ID)." )]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEClientID,

    [parameter(Mandatory = $false, HelpMessage = " Specify the serial number of a device known to Windows Autopilot." )]
    [ValidateNotNullOrEmpty()]
    [string]$WESerialNumber
)
Begin {}
Process {
    # Functions
    function WE-Invoke-MSGraphOperation {
        <#
        .SYNOPSIS
            Perform a specific call to Graph API, either as GET, POST, PATCH or DELETE methods.
            
        .DESCRIPTION
            Perform a specific call to Graph API, either as GET, POST, PATCH or DELETE methods.
            This function handles nextLink objects including throttling based on retry-after value from Graph response.
            
        .PARAMETER Get
            Switch parameter used to specify the method operation as 'GET'.
            
        .PARAMETER Post
            Switch parameter used to specify the method operation as 'POST'.
            
        .PARAMETER Patch
            Switch parameter used to specify the method operation as 'PATCH'.
            
        .PARAMETER Put
            Switch parameter used to specify the method operation as 'PUT'.
            
        .PARAMETER Delete
            Switch parameter used to specify the method operation as 'DELETE'.
            
        .PARAMETER Resource
            Specify the full resource path, e.g. deviceManagement/auditEvents.
            
        .PARAMETER Headers
            Specify a hash-table as the header containing minimum the authentication token.
            
        .PARAMETER Body
            Specify the body construct.
            
        .PARAMETER APIVersion
            Specify to use either 'Beta' or 'v1.0' API version.
            
        .PARAMETER ContentType
            Specify the content type for the graph request.
            
        .NOTES
            Author:      Nickolaj Andersen & Jan Ketil Skanke
            Contact:     @JankeSkanke @NickolajA
            Created:     2020-10-11
            Updated:     2020-11-11

            Version history:
            1.0.0 - (2020-10-11) Function created
            1.0.1 - (2020-11-11) Tested in larger environments with 100K+ resources, made small changes to nextLink handling
            1.0.2 - (2020-12-04) Added support for testing if authentication token has expired, call Get-MsalToken to refresh. This version and onwards now requires the MSAL.PS module
        #>
        [CmdletBinding()]
$ErrorActionPreference = "Stop"
param(
            [parameter(Mandatory = $true, ParameterSetName = " GET" , HelpMessage = " Switch parameter used to specify the method operation as 'GET'." )]
            [switch]$WEGet,

            [parameter(Mandatory = $true, ParameterSetName = " POST" , HelpMessage = " Switch parameter used to specify the method operation as 'POST'." )]
            [switch]$WEPost,

            [parameter(Mandatory = $true, ParameterSetName = " PATCH" , HelpMessage = " Switch parameter used to specify the method operation as 'PATCH'." )]
            [switch]$WEPatch,

            [parameter(Mandatory = $true, ParameterSetName = " PUT" , HelpMessage = " Switch parameter used to specify the method operation as 'PUT'." )]
            [switch]$WEPut,

            [parameter(Mandatory = $true, ParameterSetName = " DELETE" , HelpMessage = " Switch parameter used to specify the method operation as 'DELETE'." )]
            [switch]$WEDelete,

            [parameter(Mandatory = $true, ParameterSetName = " GET" , HelpMessage = " Specify the full resource path, e.g. deviceManagement/auditEvents." )]
            [parameter(Mandatory = $true, ParameterSetName = " POST" )]
            [parameter(Mandatory = $true, ParameterSetName = " PATCH" )]
            [parameter(Mandatory = $true, ParameterSetName = " PUT" )]
            [parameter(Mandatory = $true, ParameterSetName = " DELETE" )]
            [ValidateNotNullOrEmpty()]
            [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEResource,

            [parameter(Mandatory = $true, ParameterSetName = " GET" , HelpMessage = " Specify a hash-table as the header containing minimum the authentication token." )]
            [parameter(Mandatory = $true, ParameterSetName = " POST" )]
            [parameter(Mandatory = $true, ParameterSetName = " PATCH" )]
            [parameter(Mandatory = $true, ParameterSetName = " PUT" )]
            [parameter(Mandatory = $true, ParameterSetName = " DELETE" )]
            [ValidateNotNullOrEmpty()]
            [System.Collections.Hashtable]$WEHeaders,

            [parameter(Mandatory = $true, ParameterSetName = " POST" , HelpMessage = " Specify the body construct." )]
            [parameter(Mandatory = $true, ParameterSetName = " PATCH" )]
            [parameter(Mandatory = $true, ParameterSetName = " PUT" )]
            [ValidateNotNullOrEmpty()]
            [System.Object]$WEBody,

            [parameter(Mandatory = $false, ParameterSetName = " GET" , HelpMessage = " Specify to use either 'Beta' or 'v1.0' API version." )]
            [parameter(Mandatory = $false, ParameterSetName = " POST" )]
            [parameter(Mandatory = $false, ParameterSetName = " PATCH" )]
            [parameter(Mandatory = $false, ParameterSetName = " PUT" )]
            [parameter(Mandatory = $false, ParameterSetName = " DELETE" )]
            [ValidateNotNullOrEmpty()]
            [ValidateSet(" Beta" , " v1.0" )]
            [string]$WEAPIVersion = " v1.0" ,

            [parameter(Mandatory = $false, ParameterSetName = " GET" , HelpMessage = " Specify the content type for the graph request." )]
            [parameter(Mandatory = $false, ParameterSetName = " POST" )]
            [parameter(Mandatory = $false, ParameterSetName = " PATCH" )]
            [parameter(Mandatory = $false, ParameterSetName = " PUT" )]
            [parameter(Mandatory = $false, ParameterSetName = " DELETE" )]
            [ValidateNotNullOrEmpty()]
            [ValidateSet(" application/json" , " image/png" )]
            [string]$WEContentType = " application/json"
        )
        Begin {
            # Construct list as return value for handling both single and multiple instances in response from call
            $WEGraphResponseList = New-Object -TypeName " System.Collections.ArrayList"

            # Construct full URI
            $WEGraphURI = " https://graph.microsoft.com/$($WEAPIVersion)/$($WEResource)"
            Write-Verbose -Message " $($WEPSCmdlet.ParameterSetName) $($WEGraphURI)"
        }
        Process {
            # Call Graph API and get JSON response
            do {
                try {
                    # Determine the current time in UTC
                    $WEUTCDateTime = (Get-Date).ToUniversalTime()

                    # Determine the token expiration count as minutes
                    $WETokenExpireMins = ([datetime]$WEHeaders[" ExpiresOn" ] - $WEUTCDateTime).Minutes

                    # Attempt to retrieve a refresh token when token expiration count is less than or equal to 10
                    if ($WETokenExpireMins -le 10) {
                        Write-Verbose -Message " Existing token found but has expired, requesting a new token"
                        $WEAccessToken = Get-MsalToken -TenantId $WEScript:TenantID -ClientId $WEScript:ClientID -Silent -ForceRefresh
                        $WEHeaders = New-AuthenticationHeader -AccessToken $WEAccessToken
                    }

                    # Construct table of default request parameters
                    $WERequestParams = @{
                        " Uri" = $WEGraphURI
                        " Headers" = $WEHeaders
                        " Method" = $WEPSCmdlet.ParameterSetName
                        " ErrorAction" = " Stop"
                        " Verbose" = $false
                    }

                    switch ($WEPSCmdlet.ParameterSetName) {
                        " POST" {
                            $WERequestParams.Add(" Body" , $WEBody)
                            $WERequestParams.Add(" ContentType" , $WEContentType)
                        }
                        " PATCH" {
                            $WERequestParams.Add(" Body" , $WEBody)
                            $WERequestParams.Add(" ContentType" , $WEContentType)
                        }
                        " PUT" {
                            $WERequestParams.Add(" Body" , $WEBody)
                            $WERequestParams.Add(" ContentType" , $WEContentType)
                        }
                    }

                    # Invoke Graph request
                    $WEGraphResponse = Invoke-RestMethod @RequestParams

                    # Handle paging in response
                    if ($WEGraphResponse.'@odata.nextLink' -ne $null) {
                        $WEGraphResponseList.AddRange($WEGraphResponse.value) | Out-Null
                        $WEGraphURI = $WEGraphResponse.'@odata.nextLink'
                        Write-Verbose -Message " NextLink: $($WEGraphURI)"
                    }
                    else {
                        # NextLink from response was null, assuming last page but also handle if a single instance is returned
                        if (-not([string]::IsNullOrEmpty($WEGraphResponse.value))) {
                            $WEGraphResponseList.AddRange($WEGraphResponse.value) | Out-Null
                        }
                        else {
                            $WEGraphResponseList.Add($WEGraphResponse) | Out-Null
                        }
                        
                        # Set graph response as handled and stop processing loop
                        $WEGraphResponseProcess = $false
                    }
                }
                catch [System.Exception] {
                    $WEExceptionItem = $WEPSItem
                    if ($WEExceptionItem.Exception.Response.StatusCode -like " 429" ) {
                        # Detected throttling based from response status code
                        $WERetryInSeconds = $WEExceptionItem.Exception.Response.Headers[" Retry-After" ]

                        # Wait for given period of time specified in response headers
                        Write-Verbose -Message " Graph is throttling the request, will retry in '$($WERetryInSeconds)' seconds"
                        Start-Sleep -Seconds $WERetryInSeconds
                    }
                    else {
                        try {
                            # Read the response stream
                            $WEStreamReader = New-Object -TypeName " System.IO.StreamReader" -ArgumentList @($WEExceptionItem.Exception.Response.GetResponseStream())
                            $WEStreamReader.BaseStream.Position = 0
                            $WEStreamReader.DiscardBufferedData()
                            $WEResponseBody = ($WEStreamReader.ReadToEnd() | ConvertFrom-Json)
                            
                            switch ($WEPSCmdlet.ParameterSetName) {
                                " GET" {
                                    # Output warning message that the request failed with error message description from response stream
                                    Write-Warning -Message " Graph request failed with status code '$($WEExceptionItem.Exception.Response.StatusCode)'. Error message: $($WEResponseBody.error.message)"

                                    # Set graph response as handled and stop processing loop
                                    $WEGraphResponseProcess = $false
                                }
                                default {
                                    # Construct new custom error record
                                    $WESystemException = New-Object -TypeName " System.Management.Automation.RuntimeException" -ArgumentList (" {0}: {1}" -f $WEResponseBody.error.code, $WEResponseBody.error.message)
                                    $WEErrorRecord = New-Object -TypeName " System.Management.Automation.ErrorRecord" -ArgumentList @($WESystemException, $WEErrorID, [System.Management.Automation.ErrorCategory]::NotImplemented, [string]::Empty)

                                    # Throw a terminating custom error record
                                    $WEPSCmdlet.ThrowTerminatingError($WEErrorRecord)
                                }
                            }

                            # Set graph response as handled and stop processing loop
                            $WEGraphResponseProcess = $false
                        }
                        catch [System.Exception] {
                            Write-Warning -Message " Unhandled error occurred in function. Error message: $($WEPSItem.Exception.Message)"

                            # Set graph response as handled and stop processing loop
                            $WEGraphResponseProcess = $false
                        }
                    }
                }
            }
            until ($WEGraphResponseProcess -eq $false)

            # Handle return value
            return $WEGraphResponseList
        }
    }

    function WE-New-AuthenticationHeader {
        <#
        .SYNOPSIS
            Construct a required header hash-table based on the access token from Get-MsalToken cmdlet.

        .DESCRIPTION
            Construct a required header hash-table based on the access token from Get-MsalToken cmdlet.

        .PARAMETER AccessToken
            Pass the AuthenticationResult object returned from Get-MsalToken cmdlet.

        .NOTES
            Author:      Nickolaj Andersen
            Contact:     @NickolajA
            Created:     2020-12-04
            Updated:     2020-12-04

            Version history:
            1.0.0 - (2020-12-04) Script created
        #>
        [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [parameter(Mandatory = $true, HelpMessage = " Pass the AuthenticationResult object returned from Get-MsalToken cmdlet." )]
            [ValidateNotNullOrEmpty()]
            [Microsoft.Identity.Client.AuthenticationResult]$WEAccessToken
        )
        Process {
            # Construct default header parameters
            $WEAuthenticationHeader = @{
                " Content-Type" = " application/json"
                " Authorization" = $WEAccessToken.CreateAuthorizationHeader()
                " ExpiresOn" = $WEAccessToken.ExpiresOn.LocalDateTime
            }

            # Amend header with additional required parameters for bitLocker/recoveryKeys resource query
            $WEAuthenticationHeader.Add(" ocp-client-name" , " My App" )
            $WEAuthenticationHeader.Add(" ocp-client-version" , " 1.0" )

            # Handle return value
            return $WEAuthenticationHeader
        }
    }

    function WE-Get-AutopilotDevice {
        <#
        .SYNOPSIS
            Retrieve an Autopilot device identity based on serial number.
            
        .DESCRIPTION
            Retrieve an Autopilot device identity based on serial number.
            
        .PARAMETER SerialNumber
            Specify the serial number of the device.
            
        .NOTES
            Author:      Nickolaj Andersen
            Contact:     @NickolajA
            Created:     2021-01-27
            Updated:     2021-01-27
    
            Version history:
            1.0.0 - (2021-01-27) Function created
        #>    
        [CmdletBinding()]
$ErrorActionPreference = "Stop"
param(
            [parameter(Mandatory = $true, HelpMessage = " Specify the serial number of the device." )]
            [ValidateNotNullOrEmpty()]
            [string]$WESerialNumber
        )
        Process {
            # Retrieve the Windows Autopilot device identity by filtering on serialNumber property with passed parameter input
            $WESerialNumberEncoded = [Uri]::EscapeDataString($WESerialNumber)
            $WEResourceURI = " deviceManagement/windowsAutopilotDeviceIdentities?`$filter=contains(serialNumber,'$($WESerialNumberEncoded)')"
            $WEGraphResponse = (Invoke-MSGraphOperation -Get -APIVersion " Beta" -Resource $WEResourceURI -Headers $WEScript:AuthenticationHeader).value
    
            # Handle return response
            return $WEGraphResponse
        }    
    }

    try {
        # Determine the correct RedirectUri (also known as Reply URL) to use with MSAL.PS
        if ($WEClientID -like " d1ddf0e4-d672-4dae-b554-9d5bdfd93547" ) {
            $WERedirectUri = " urn:ietf:wg:oauth:2.0:oob"
        }
        else {
            $WERedirectUri = [string]::Empty
        }

        # Get authentication token
        $WEAccessToken = Get-MsalToken -TenantId $WETenantID -ClientId $WEClientID -RedirectUri $WERedirectUri -ErrorAction Stop

        # Construct authentication header
        $WEAuthenticationHeader = New-AuthenticationHeader -AccessToken $WEAccessToken

        # Construct a new list to contain all device records
        $WEDeviceList = New-Object -TypeName System.Collections.ArrayList

        try {
            # Retrieve the Autopilot device identity based on serial number from parameter input
            $WEAutopilotDevice = Get-AutopilotDevice -SerialNumber $WESerialNumber -ErrorAction Stop

            try {
                # Determine the hardware identifier for the associated Azure AD device record of the Autopilot device identity
                $WEPhysicalIds = (Invoke-MSGraphOperation -Get -APIVersion " v1.0" -Resource " devices?`$filter=deviceId eq '$($WEAutopilotDevice.azureActiveDirectoryDeviceId)'" -Headers $WEAuthenticationHeader).value.physicalIds
                $WEHardwareID = $WEPhysicalIds | Where-Object { $WEPSItem -match " ^\[HWID\]:h:.*$" }

                if ($WEHardwareID -ne $null) {
                    # Retrieve all Azure AD device records matching the given hardware identifier
                   ;  $WEDevicesResponse = (Invoke-MSGraphOperation -Get -APIVersion " v1.0" -Resource " devices?`$filter=physicalIds/any(c:c eq '$($WEHardwareID)')" -Headers $WEAuthenticationHeader)
                    if ($WEDevicesResponse.value -eq $null) {
                        foreach ($WEResponse in $WEDevicesResponse) {
                            $WEDeviceList.Add($WEResponse) | Out-Null
                        }
                    }
                    else {
                        $WEDeviceList.Add($WEDevicesResponse.value) | Out-Null
                    }

                    # Handle output
                    foreach ($WEDevice in $WEDeviceList) {
                       ;  $WEPSObject = [PSCustomObject]@{
                            DeviceName = $WEDevice.displayName
                            DeviceID = $WEDevice.deviceId
                            ObjectID = $WEDevice.id
                            HardwareID = $WEHardwareID
                            Created = [datetime]::Parse($WEDevice.createdDateTime)
                            LastSignIn = [datetime]::Parse($WEDevice.approximateLastSignInDateTime)
                            TrustType = $WEDevice.trustType
                            Autopilot = if ($WEDevice.deviceId -like $WEAutopilotDevice.azureActiveDirectoryDeviceId) { $true } else { $false }
                        }
                        Write-Output -InputObject $WEPSObject
                    }
                }
                else {
                    " ..."
                }
            }
            catch [System.Exception] {
                Write-Warning -Message " An error occurred while .... Error message: $($WEPSItem.Exception.Message)"
            }
        }
        catch [System.Exception] {
            Write-Warning -Message " An error occurred while .... Error message: $($WEPSItem.Exception.Message)"
        }
    }
    catch [System.Exception] {
        Write-Warning -Message " An error occurred while attempting to retrieve an authentication token. Error message: $($WEPSItem.Exception.Message)"
    }
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================