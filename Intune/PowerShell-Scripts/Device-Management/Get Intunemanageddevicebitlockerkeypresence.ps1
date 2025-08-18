<#
.SYNOPSIS
    Get Intunemanageddevicebitlockerkeypresence

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
    We Enhanced Get Intunemanageddevicebitlockerkeypresence

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
    Get the BitLocker recovery key presence for Intune managed devices.

.DESCRIPTION
    This script retrieves the BitLocker recovery key presence for Intune managed devices.

.PARAMETER TenantID
    Specify the Azure AD tenant ID.

.PARAMETER ClientID
    Specify the service principal, also known as app registration, Client ID (also known as Application ID).

.PARAMETER State
    Specify either 'Present' or 'NotPresent'.

.EXAMPLE
    # Retrieve a list of Intune managed devices that have a BitLocker recovery key associated on the Azure AD device object:
    .\Get-IntuneManagedDeviceBitLockerKeyPresence.ps1 -TenantID " <tenant_id>" -ClientID " <client_id>"

    # Retrieve a list of Intune managed devices that doesn't have a BitLocker recovery key associated on the Azure AD device object:
    .\Get-IntuneManagedDeviceBitLockerKeyPresence.ps1 -TenantID " <tenant_id>" -ClientID " <client_id>" -State " NotPresent"

.NOTES
    FileName:    Get-IntuneManagedDeviceBitLockerKeyPresence.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2020-12-04
    Updated:     2020-12-04

    Version history:
    1.0.0 - (2020-12-04) Script created

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

    [parameter(Mandatory = $false, HelpMessage = " Specify either 'Present' or 'NotPresent'." )]
    [ValidateNotNullOrEmpty()]
    [ValidateSet(" NotPresent" , " Present" )]
    [string]$WEState = " Present"
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
$ErrorActionPreference = " Stop"
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
    
    try {
        # Get authentication token
        $WEAccessToken = Get-MsalToken -TenantId $WETenantID -ClientId $WEClientID -ErrorAction Stop

        # Construct authentication header
        $WEAuthenticationHeader = New-AuthenticationHeader -AccessToken $WEAccessToken
        
        # Retrieve all available BitLocker recovery keys, select only desired properties
       ;  $WEBitLockerRecoveryKeys = Invoke-MSGraphOperation -Get -APIVersion " Beta" -Resource " bitlocker/recoveryKeys?`$select=id,createdDateTime,deviceId" -Headers $WEAuthenticationHeader -Verbose:$WEVerbosePreference
        
        # Retrieve all managed Windows devices in Intune
       ;  $WEManagedDevices = Invoke-MSGraphOperation -Get -APIVersion " v1.0" -Resource " deviceManagement/managedDevices?`$filter=operatingSystem eq 'Windows'&select=azureADDeviceId&`$select=deviceName,id,azureADDeviceId" -Headers $WEAuthenticationHeader -Verbose:$WEVerbosePreference
        
        # Define behavior for managed device selection
        switch ($WEState) {
            " Present" {
                $WEManagedDevices | Where-Object { $WEPSItem.azureADDeviceId -in $WEBitLockerRecoveryKeys.deviceId }
            }
            " NotPresent" {
                $WEManagedDevices | Where-Object { $WEPSItem.azureADDeviceId -notin $WEBitLockerRecoveryKeys.deviceId }
            }
        }
    }
    catch [System.Exception] {
        Write-Warning -Message " An error occurred while attempting to retrieve an authentication token. Error message: $($WEPSItem.Exception.Message)"
    }
}


# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================