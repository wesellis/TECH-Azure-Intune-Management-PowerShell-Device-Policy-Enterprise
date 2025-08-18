<#
.SYNOPSIS
    Set Autopilotdevicegrouptag

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
    We Enhanced Set Autopilotdevicegrouptag

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
    Set the Group Tag of an explicit Autopilot device or an array of devices to a specific value.

.DESCRIPTION
    This script will set the Group Tag of an explicit Autopilot device or an array of devices. The serial number
    of a device, or multiple, are used as the device idenfier in the Autopilot service. All devices will get the 
    same static Group Tag value, used as input for the Value parameter.

.PARAMETER TenantID
    Specify the Azure AD tenant ID or the common name, e.g. 'tenant.onmicrosoft.com'.

.PARAMETER ClientID
    Specify the service principal (also known as an app registration) Client ID (also known as Application ID).

.PARAMETER SerialNumber
    Specify an explicit or an array of serial numbers, to be used as the identifier when querying the Autopilot service for devices.

.PARAMETER Value
    Specify the Group Tag value to be set for all identified devices.

.EXAMPLE
    # Update the Group Tag of a device with serial number '1234567', with a value of 'GroupTag1':
    .\Set-AutopilotDeviceGroupTag.ps1 -TenantID " tenant.onmicrosoft.com" -ClientID " <guid>" -SerialNumber " 1234567" -Value " GroupTag1"

    # Update the Group Tag of a multiple devices in an array, with a value of 'GroupTag1':
    .\Set-AutopilotDeviceGroupTag.ps1 -TenantID " tenant.onmicrosoft.com" -ClientID " <guid>" -SerialNumber @(" 1234567" , " 2345678" ) -Value " GroupTag1"

.NOTES
    FileName:    Set-AutopilotDeviceGroupTag.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2021-02-21
    Updated:     2021-02-21

    Version history:
    1.0.0 - (2021-02-21) Script created

[CmdletBinding(SupportsShouldProcess = $true)]
[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [parameter(Mandatory = $true, HelpMessage = " Specify the Azure AD tenant ID or the common name, e.g. 'tenant.onmicrosoft.com'." )]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WETenantID,

    [parameter(Mandatory = $true, HelpMessage = " Specify the service principal (also known as an app registration) Client ID (also known as Application ID)." )]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEClientID,

    [parameter(Mandatory = $true, HelpMessage = " Specify an explicit or an array of serial numbers, to be used as the identifier when querying the Autopilot service for devices." )]
    [ValidateNotNullOrEmpty()]
    [string[]]$WESerialNumber,

    [parameter(Mandatory = $true, HelpMessage = " Specify the Group Tag value to be set for all identified devices." )]
    [ValidateNotNullOrEmpty()]
    [string]$WEValue
)
Begin {}
Process {
    # Functions
    [CmdletBinding()]
function WE-New-AuthenticationHeader -ErrorAction Stop {
        <#
        .SYNOPSIS
            Construct a required header hash-table based on the access token from Get-MsalToken -ErrorAction Stop cmdlet.

        .DESCRIPTION
            Construct a required header hash-table based on the access token from Get-MsalToken -ErrorAction Stop cmdlet.

        .PARAMETER AccessToken
            Pass the AuthenticationResult object returned from Get-MsalToken -ErrorAction Stop cmdlet.

        .NOTES
            Author:      Nickolaj Andersen
            Contact:     @NickolajA
            Created:     2020-12-04
            Updated:     2020-12-04

            Version history:
            1.0.0 - (2020-12-04) Script created
        #>
        [CmdletBinding()]
$ErrorActionPreference = "Stop"
param(
            [parameter(Mandatory = $true, HelpMessage = " Pass the AuthenticationResult object returned from Get-MsalToken -ErrorAction Stop cmdlet." )]
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

    [CmdletBinding()]
function WE-Invoke-MSGraphOperation {
        <#
        .SYNOPSIS
            Perform a specific call to Intune Graph API, either as GET, POST, PATCH or DELETE methods.
            
        .DESCRIPTION
            Perform a specific call to Intune Graph API, either as GET, POST, PATCH or DELETE methods.
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
            1.0.1 - (2020-11-11) Verified
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
    
            [parameter(Mandatory = $false, ParameterSetName = " POST" , HelpMessage = " Specify the body construct." )]
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
                            if ($WEPSBoundParameters[" Body" ]) {
                                $WERequestParams.Add(" Body" , $WEBody)
                            }
                            if (-not([string]::IsNullOrEmpty($WEContentType))) {
                                $WERequestParams.Add(" ContentType" , $WEContentType)
                            }
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
                    # Capture current error
                    $WEExceptionItem = $WEPSItem
    
                    # Read the response stream
                    $WEStreamReader = New-Object -TypeName " System.IO.StreamReader" -ArgumentList @($WEExceptionItem.Exception.Response.GetResponseStream()) -ErrorAction SilentlyContinue
                    if ($null -ne $WEStreamReader) {
                        $WEStreamReader.BaseStream.Position = 0
                        $WEStreamReader.DiscardBufferedData()
                        $WEResponseBody = ($WEStreamReader.ReadToEnd() | ConvertFrom-Json)
        
                        if ($WEExceptionItem.Exception.Response.StatusCode -like " 429" ) {
                            # Detected throttling based from response status code
                            $WERetryInSeconds = $WEExceptionItem.Exception.Response.Headers[" Retry-After" ]
        
                            if ($null -ne $WERetryInSeconds) {
                                # Wait for given period of time specified in response headers
                                Write-Verbose -Message " Graph is throttling the request, will retry in '$($WERetryInSeconds)' seconds"
                                Start-Sleep -Seconds $WERetryInSeconds
                            }
                            else {
                                Write-Verbose -Message " Graph is throttling the request, will retry in default '300' seconds"
                                Start-Sleep -Seconds 300
                            }
                        }
                        else {
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
                    }
                    else {
                        Write-Warning -Message " Failed with message: $($WEExceptionItem.Exception.Message)"
    
                        # Set graph response as handled and stop processing loop
                        $WEGraphResponseProcess = $false
                    }
                }
            }
            until ($WEGraphResponseProcess -eq $false)
    
            # Handle return value
            return $WEGraphResponseList
        }
    }
    
    [CmdletBinding()]
function WE-Get-AutopilotDevice -ErrorAction Stop {
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
            Created:     2021-02-21
            Updated:     2021-02-21
    
            Version history:
            1.0.0 - (2021-02-21) Function created
        #>    
        [CmdletBinding()]
$ErrorActionPreference = " Stop"
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
    
    [CmdletBinding()]
function WE-Set-AutopilotDevice -ErrorAction Stop {
        <#
        .SYNOPSIS
            Update the GroupTag for an Autopilot device identity.
            
        .DESCRIPTION
            Update the GroupTag for an Autopilot device identity.
            
        .PARAMETER Id
            Specify the Autopilot device identity id.
    
        .PARAMETER GroupTag
            Specify the Group Tag string value.
            
        .NOTES
            Author:      Nickolaj Andersen
            Contact:     @NickolajA
            Created:     2021-02-21
            Updated:     2021-02-21
    
            Version history:
            1.0.0 - (2021-02-21) Function created
        #>
        [CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
            [parameter(Mandatory = $true, HelpMessage = " Specify the Autopilot device identity id." )]
            [ValidateNotNullOrEmpty()]
            [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEId,
    
            [parameter(Mandatory = $true, HelpMessage = " Specify the Group Tag string value." )]
            [ValidateNotNullOrEmpty()]
            [string]$WEGroupTag
        )
        Process {
            # Construct JSON post body content
            $WEBodyTable = @{
                " groupTag" = $WEGroupTag
            }
            $WEBodyJSON = ConvertTo-Json -InputObject $WEBodyTable
    
            # Update Autopilot device properties with new group tag string
            $WEResourceURI = " deviceManagement/windowsAutopilotDeviceIdentities/$($WEId)/UpdateDeviceProperties"
            $WEGraphResponse = Invoke-MSGraphOperation -Post -APIVersion " Beta" -Resource $WEResourceURI -Headers $WEScript:AuthenticationHeader -Body $WEBodyJSON -ContentType " application/json"
    
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

        try {
            # Construct authentication header
            $WEAuthenticationHeader = New-AuthenticationHeader -AccessToken $WEAccessToken -ErrorAction Stop

            try {
                # Construct list to hold all Autopilot device objects
                $WEAutopilotDevices = New-Object -TypeName " System.Collections.ArrayList"
                
                # Retrieve list of Autopilot devices based on parameter input from SerialNumber
                foreach ($WESerialNumberItem in $WESerialNumber) {
                    Write-Verbose -Message " Attempting to get Autopilot device with serial number: $($WESerialNumberItem)"
                    $WEAutopilotDevice = Get-AutopilotDevice -SerialNumber $WESerialNumberItem -ErrorAction Stop
                    if ($null -ne $WEAutopilotDevice) {
                        $WEAutopilotDevices.Add($WEAutopilotDevice) | Out-Null
                    }
                    else {
                        Write-Warning -Message " Unable to get Autopilot device with serial number: $($WESerialNumberItem)"
                    }
                }

                # Set group tag for all identified Autopilot devices
                if ($WEAutopilotDevices.Count -ge 1) {
                    if ($WEPSCmdlet.ShouldProcess(" $($WEAutopilotDevices.Count) Autopilot devices" , " Set Group Tag" )) {
                        foreach ($WEAutopilotDevice in $WEAutopilotDevices) {
                            try {
                                # Set group tag for current Autopilot device
                                Write-Verbose -Message " Setting Group Tag value '$($WEValue)' for Autopilot device: $($WEAutopilotDevice.serialNumber)"
                                Set-AutopilotDevice -Id $WEAutopilotDevice.id -GroupTag $WEValue -ErrorAction Stop

                                # Handle success output
                               ;  $WEPSObject = [PSCustomObject]@{
                                    SerialNumber = $WEAutopilotDevice.serialNumber
                                    GroupTag = $WEValue
                                    Result = " Success"
                                }
                            }
                            catch [System.Exception] {
                                Write-Warning -Message " An error occurred while setting the Group Tag for Autopilot device with serial number '$($WEAutopilotDevices.serialNumber)'. Error message: $($WEPSItem.Exception.Message)"

                                # Handle failure output
                               ;  $WEPSObject = [PSCustomObject]@{
                                    SerialNumber = $WEAutopilotDevice.serialNumber
                                    GroupTag = $WEValue
                                    Result = " Success"
                                }
                            }

                            # Handle current item output return
                            Write-Output -InputObject $WEPSObject
                        }
                    }
                }
            }
            catch [System.Exception] {
                Write-Warning -Message " An error occurred while retrieving all Autopilot devices matching serial number input. Error message: $($WEPSItem.Exception.Message)"
            }
        }
        catch [System.Exception] {
            Write-Warning -Message " An error occurred while constructing the authentication header. Error message: $($WEPSItem.Exception.Message)"
        }
    }
    catch [System.Exception] {
        Write-Warning -Message " An error occurred while attempting to retrieve an authentication token. Error message: $($WEPSItem.Exception.Message)"
    }
}



# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================