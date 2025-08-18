<#
.SYNOPSIS
    Win32 Application Add

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
    We Enhanced Win32 Application Add

.DESCRIPTION
    Professional PowerShell script for enterprise automation.
    Optimized for performance, reliability, and error handling.

.AUTHOR
    Enterprise PowerShell Framework

.VERSION
    1.0

.NOTES
    Requires appropriate permissions and modules


[CmdletBinding()]
function WE-Test-RequiredPath {
    [CmdletBinding()]
$ErrorActionPreference = "Stop"
param([Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEPath)
    if (!(Test-Path $WEPath)) {
        Write-Warning " Required path not found: $WEPath"
        return $false
    }
    return $true
}


<#



$WEErrorActionPreference = " Stop"
$WEVerbosePreference = if ($WEPSBoundParameters.ContainsKey('Verbose')) { " Continue" } else { " SilentlyContinue" }

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.





[CmdletBinding()]
function WE-Get-AuthToken -ErrorAction Stop {

<#
.SYNOPSIS
This function is used to authenticate with the Graph API REST interface
.DESCRIPTION
The function authenticate with the Graph API Interface with the tenant name
.EXAMPLE
Get-AuthToken -ErrorAction Stop
Authenticates you with the Graph API interface
.NOTES
NAME: Get-AuthToken -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Parameter(Mandatory=$true)]
    $WEUser
)

$userUpn = New-Object -ErrorAction Stop " System.Net.Mail.MailAddress" -ArgumentList $WEUser

$tenant = $userUpn.Host

Write-WELog " Checking for AzureAD module..." " INFO"

    $WEAadModule = Get-Module -Name " AzureAD" -ListAvailable

    if ($null -eq $WEAadModule) {

        Write-WELog " AzureAD PowerShell module not found, looking for AzureADPreview" " INFO"
        $WEAadModule = Get-Module -Name " AzureADPreview" -ListAvailable

    }

    if ($null -eq $WEAadModule) {
        Write-Information write-host " AzureAD Powershell module not installed..." -f Red
        Write-Information " Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
        Write-Information " Script can't continue..." -f Red
        Write-Information exit
    }



    if($WEAadModule.count -gt 1){

        $WELatest_Version = ($WEAadModule | select version | Sort-Object)[-1]

        $aadModule = $WEAadModule | ? { $_.version -eq $WELatest_Version.version }

            # Checking if there are multiple versions of the same module found

            if($WEAadModule.count -gt 1){

            $aadModule = $WEAadModule | select -Unique

            }

        $adal = Join-Path $WEAadModule.ModuleBase " Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $WEAadModule.ModuleBase " Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

    else {

        $adal = Join-Path $WEAadModule.ModuleBase " Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $WEAadModule.ModuleBase " Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

[System.Reflection.Assembly]::LoadFrom($adal) | Out-Null

[System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null



$clientId = " <replace with your clientID>"

$redirectUri = " urn:ietf:wg:oauth:2.0:oob"

$resourceAppIdURI = " https://graph.microsoft.com"

$authority = " https://login.microsoftonline.com/$WETenant"

    try {

    $authContext = New-Object -ErrorAction Stop " Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority

    # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
    # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession

    $platformParameters = New-Object -ErrorAction Stop " Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList " Auto"

    $userId = New-Object -ErrorAction Stop " Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($WEUser, " OptionalDisplayableId" )

    $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId).Result

        # If the accesstoken is valid then create the authentication header

        if($authResult.AccessToken){

        # Creating header for Authorization token

       ;  $authHeader = @{
            'Content-Type'='application/json'
            'Authorization'=" Bearer " + $authResult.AccessToken
            'ExpiresOn'=$authResult.ExpiresOn
            }

        return $authHeader

        }

        else {

        Write-Information Write-WELog " Authorization Access Token is null, please re-run authentication..." " INFO"
        Write-Information break

        }

    }

    catch {

    Write-Information $_.Exception.Message -f Red
    Write-Information $_.Exception.ItemName -f Red
    Write-Information break

    }

}
 


function WE-CloneObject($object){

; 	$stream = New-Object -ErrorAction Stop IO.MemoryStream;
	$formatter = New-Object -ErrorAction Stop Runtime.Serialization.Formatters.Binary.BinaryFormatter;
	$formatter.Serialize($stream, $object);
	$stream.Position = 0;
	$formatter.Deserialize($stream);
}



function WE-WriteHeaders($authToken){

	foreach ($header in $authToken.GetEnumerator())
	{
		if ($header.Name.ToLower() -eq " authorization" )
		{
			continue;
		}

		Write-Information -ForegroundColor Gray " $($header.Name): $($header.Value)" ;
	}
}



function WE-MakeGetRequest($collectionPath){

	$uri = " $baseUrl$collectionPath" ;
	$request = " GET $uri" ;
	
	if ($logRequestUris) { Write-Information $request; }
	if ($logHeaders) { WriteHeaders $authToken; }

	try
	{
		Test-AuthToken
		$response = Invoke-RestMethod $uri -Method Get -Headers $authToken;
		$response;
	}
	catch
	{
		Write-Information -ForegroundColor Red $request;
		Write-Information -ForegroundColor Red $_.Exception.Message;
		throw;
	}
}



function WE-MakePatchRequest($collectionPath, $body){

	MakeRequest " PATCH" $collectionPath $body;

}



function WE-MakePostRequest($collectionPath, $body){

	MakeRequest " POST" $collectionPath $body;

}



function WE-MakeRequest($verb, $collectionPath, $body){

	$uri = " $baseUrl$collectionPath" ;
	$request = " $verb $uri" ;
	
	$clonedHeaders = CloneObject $authToken;
	$clonedHeaders[" content-length" ] = $body.Length;
	$clonedHeaders[" content-type" ] = " application/json" ;

	if ($logRequestUris) { Write-Information $request; }
	if ($logHeaders) { WriteHeaders $clonedHeaders; }
	if ($logContent) { Write-Information -ForegroundColor Gray $body; }

	try
	{
		Test-AuthToken
		$response = Invoke-RestMethod $uri -Method $verb -Headers $clonedHeaders -Body $body;
		$response;
	}
	catch
	{
		Write-Information -ForegroundColor Red $request;
		Write-Information -ForegroundColor Red $_.Exception.Message;
		throw;
	}
}



function WE-UploadAzureStorageChunk($sasUri, $id, $body){

	$uri = " $sasUri&comp=block&blockid=$id" ;
	$request = " PUT $uri" ;

	$iso = [System.Text.Encoding]::GetEncoding(" iso-8859-1" );
	$encodedBody = $iso.GetString($body);
	$headers = @{
		" x-ms-blob-type" = " BlockBlob"
	};

	if ($logRequestUris) { Write-Information $request; }
	if ($logHeaders) { WriteHeaders $headers; }

	try
	{
		$response = Invoke-WebRequest $uri -Method Put -Headers $headers -Body $encodedBody;
	}
	catch
	{
		Write-Information -ForegroundColor Red $request;
		Write-Information -ForegroundColor Red $_.Exception.Message;
		throw;
	}

}



function WE-FinalizeAzureStorageUpload($sasUri, $ids){

	$uri = " $sasUri&comp=blocklist" ;
	$request = " PUT $uri" ;

	$xml = '<?xml version=" 1.0" encoding=" utf-8" ?><BlockList>';
	foreach ($id in $ids)
	{
		$xml = $xml + " <Latest>$id</Latest>" ;
	}
	$xml = $xml + '</BlockList>';

	if ($logRequestUris) { Write-Information $request; }
	if ($logContent) { Write-Information -ForegroundColor Gray $xml; }

	try
	{
		Invoke-RestMethod $uri -Method Put -Body $xml;
	}
	catch
	{
		Write-Information -ForegroundColor Red $request;
		Write-Information -ForegroundColor Red $_.Exception.Message;
		throw;
	}
}



function WE-UploadFileToAzureStorage($sasUri, $filepath, $fileUri){

	try {

        $chunkSizeInBytes = 1024l * 1024l * $azureStorageUploadChunkSizeInMb;
		
		# Start the timer for SAS URI renewal.
		$sasRenewalTimer = [System.Diagnostics.Stopwatch]::StartNew()
		
		# Find the file size and open the file.
	; 	$fileSize = (Get-Item -ErrorAction Stop $filepath).length;
		$chunks = [Math]::Ceiling($fileSize / $chunkSizeInBytes);
		$reader = New-Object -ErrorAction Stop System.IO.BinaryReader([System.IO.File]::Open($filepath, [System.IO.FileMode]::Open));
		$position = $reader.BaseStream.Seek(0, [System.IO.SeekOrigin]::Begin);
		
		# Upload each chunk. Check whether a SAS URI renewal is required after each chunk is uploaded and renew if needed.
		$ids = @();

		for ($chunk = 0; $chunk -lt $chunks; $chunk++){

			$id = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($chunk.ToString(" 0000" )));
			$ids = $ids + $id;

			$start = $chunk * $chunkSizeInBytes;
			$length = [Math]::Min($chunkSizeInBytes, $fileSize - $start);
			$bytes = $reader.ReadBytes($length);
			
			$currentChunk = $chunk + 1;			

            Write-Progress -Activity " Uploading File to Azure Storage" -status " Uploading chunk $currentChunk of $chunks" `
            -percentComplete ($currentChunk / $chunks*100)

            $uploadResponse = UploadAzureStorageChunk $sasUri $id $bytes;
			
			# Renew the SAS URI if 7 minutes have elapsed since the upload started or was renewed last.
			if ($currentChunk -lt $chunks -and $sasRenewalTimer.ElapsedMilliseconds -ge 450000){

				$renewalResponse = RenewAzureStorageUpload $fileUri;
				$sasRenewalTimer.Restart();
			
            }

		}

        Write-Progress -Completed -Activity " Uploading File to Azure Storage"

		$reader.Close();

	}

	finally {

		if ($null -ne $reader) { $reader.Dispose(); }
	
    }
	
	# Finalize the upload.
	$uploadResponse = FinalizeAzureStorageUpload $sasUri $ids;

}



function WE-RenewAzureStorageUpload($fileUri){

	$renewalUri = " $fileUri/renewUpload" ;
	$actionBody = "" ;
	$rewnewUriResult = MakePostRequest $renewalUri $actionBody;
	
	$file = WaitForFileProcessing $fileUri " AzureStorageUriRenewal" $azureStorageRenewSasUriBackOffTimeInSeconds;

}



function WE-WaitForFileProcessing($fileUri, $stage){

	$attempts= 600;
	$waitTimeInSeconds = 10;

	$successState = " $($stage)Success" ;
	$pendingState = " $($stage)Pending" ;
	$failedState = " $($stage)Failed" ;
	$timedOutState = " $($stage)TimedOut" ;

	$file = $null;
	while ($attempts -gt 0)
	{
		$file = MakeGetRequest $fileUri;

		if ($file.uploadState -eq $successState)
		{
			break;
		}
		elseif ($file.uploadState -ne $pendingState)
		{
			Write-Information -ForegroundColor Red $_.Exception.Message;
            throw " File upload state is not success: $($file.uploadState)" ;
		}

		Start-Sleep $waitTimeInSeconds;
		$attempts--;
	}

	if ($null -eq $file -or $file.uploadState -ne $successState)
	{
		throw " File request did not complete in the allotted time." ;
	}

	$file;
}



function WE-GetWin32AppBody(){

[CmdletBinding()]
$ErrorActionPreference = "Stop"
param(
[parameter(Mandatory=$true,ParameterSetName = " MSI" ,Position=1)]
[Switch]$WEMSI,

[parameter(Mandatory=$true,ParameterSetName = " EXE" ,Position=1)]
[Switch]$WEEXE,

[parameter(Mandatory=$true)]
[ValidateNotNullOrEmpty()]
[Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$displayName,

[parameter(Mandatory=$true)]
[ValidateNotNullOrEmpty()]
[Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$publisher,

[parameter(Mandatory=$true)]
[ValidateNotNullOrEmpty()]
[Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$description,

[parameter(Mandatory=$true)]
[ValidateNotNullOrEmpty()]
[Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$filename,

[parameter(Mandatory=$true)]
[ValidateNotNullOrEmpty()]
[Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WESetupFileName,

[parameter(Mandatory=$true)]
[ValidateSet('system','user')]; 
$installExperience = " system" ,

[parameter(Mandatory=$true,ParameterSetName = " EXE" )]
[ValidateNotNullOrEmpty()]
$installCommandLine,

[parameter(Mandatory=$true,ParameterSetName = " EXE" )]
[ValidateNotNullOrEmpty()]
$uninstallCommandLine,

[parameter(Mandatory=$true,ParameterSetName = " MSI" )]
[ValidateNotNullOrEmpty()]
$WEMsiPackageType,

[parameter(Mandatory=$true,ParameterSetName = " MSI" )]
[ValidateNotNullOrEmpty()]
$WEMsiProductCode,

[parameter(Mandatory=$false,ParameterSetName = " MSI" )]
$WEMsiProductName,

[parameter(Mandatory=$true,ParameterSetName = " MSI" )]
[ValidateNotNullOrEmpty()]
$WEMsiProductVersion,

[parameter(Mandatory=$false,ParameterSetName = " MSI" )]
$WEMsiPublisher,

[parameter(Mandatory=$true,ParameterSetName = " MSI" )]
[ValidateNotNullOrEmpty()]
$WEMsiRequiresReboot,

[parameter(Mandatory=$true,ParameterSetName = " MSI" )]
[ValidateNotNullOrEmpty()]
$WEMsiUpgradeCode

)

    if($WEMSI){

	   ;  $body = @{ " @odata.type" = " #microsoft.graph.win32LobApp" };
        $body.applicableArchitectures = " x64,x86" ;
        $body.description = $description;
	    $body.developer = "" ;
	    $body.displayName = $displayName;
	    $body.fileName = $filename;
        $body.installCommandLine = " msiexec /i `" $WESetupFileName`""
        $body.installExperience = @{" runAsAccount" = " $installExperience" };
	    $body.informationUrl = $null;
	    $body.isFeatured = $false;
        $body.minimumSupportedOperatingSystem = @{" v10_1607" = $true};
        $body.msiInformation = @{
            " packageType" = " $WEMsiPackageType" ;
            " productCode" = " $WEMsiProductCode" ;
            " productName" = " $WEMsiProductName" ;
            " productVersion" = " $WEMsiProductVersion" ;
            " publisher" = " $WEMsiPublisher" ;
            " requiresReboot" = " $WEMsiRequiresReboot" ;
            " upgradeCode" = " $WEMsiUpgradeCode"
        };
	    $body.notes = "" ;
	    $body.owner = "" ;
	    $body.privacyInformationUrl = $null;
	    $body.publisher = $publisher;
        $body.runAs32bit = $false;
        $body.setupFilePath = $WESetupFileName;
        $body.uninstallCommandLine = " msiexec /x `" $WEMsiProductCode`""

    }

    elseif($WEEXE){

        $body = @{ " @odata.type" = " #microsoft.graph.win32LobApp" };
        $body.description = $description;
	    $body.developer = "" ;
	    $body.displayName = $displayName;
	    $body.fileName = $filename;
        $body.installCommandLine = " $installCommandLine"
        $body.installExperience = @{" runAsAccount" = " $installExperience" };
	    $body.informationUrl = $null;
	    $body.isFeatured = $false;
        $body.minimumSupportedOperatingSystem = @{" v10_1607" = $true};
        $body.msiInformation = $null;
	    $body.notes = "" ;
	    $body.owner = "" ;
	    $body.privacyInformationUrl = $null;
	    $body.publisher = $publisher;
        $body.runAs32bit = $false;
        $body.setupFilePath = $WESetupFileName;
        $body.uninstallCommandLine = " $uninstallCommandLine"

    }

	$body;
}



function WE-GetAppFileBody($name, $size, $sizeEncrypted, $manifest){

	$body = @{ " @odata.type" = " #microsoft.graph.mobileAppContentFile" };
	$body.name = $name;
	$body.size = $size;
	$body.sizeEncrypted = $sizeEncrypted;
	$body.manifest = $manifest;
    $body.isDependency = $false;

	$body;
}



function WE-GetAppCommitBody($contentVersionId, $WELobType){

	$body = @{ " @odata.type" = " #$WELobType" };
	$body.committedContentVersion = $contentVersionId;

	$body;

}



Function Test-SourceFile(){

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    $WESourceFile
)

    try {

            if(!(test-path " $WESourceFile" )){

            Write-Information Write-WELog " Source File '$sourceFile' doesn't exist..." " INFO"
            throw

            }

        }

    catch {

		Write-Information -ForegroundColor Red $_.Exception.Message;
        Write-Information break

    }

}



Function New-DetectionRule(){

[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
 [parameter(Mandatory=$true,ParameterSetName = " PowerShell" ,Position=1)]
 [Switch]$WEPowerShell,

 [parameter(Mandatory=$true,ParameterSetName = " MSI" ,Position=1)]
 [Switch]$WEMSI,

 [parameter(Mandatory=$true,ParameterSetName = " File" ,Position=1)]
 [Switch]$WEFile,

 [parameter(Mandatory=$true,ParameterSetName = " Registry" ,Position=1)]
 [Switch]$WERegistry,

 [parameter(Mandatory=$true,ParameterSetName = " PowerShell" )]
 [ValidateNotNullOrEmpty()]
 [String]$WEScriptFile,

 [parameter(Mandatory=$true,ParameterSetName = " PowerShell" )]
 [ValidateNotNullOrEmpty()]
 $enforceSignatureCheck,

 [parameter(Mandatory=$true,ParameterSetName = " PowerShell" )]
 [ValidateNotNullOrEmpty()]
 $runAs32Bit,

 [parameter(Mandatory=$true,ParameterSetName = " MSI" )]
 [ValidateNotNullOrEmpty()]
 [String]$WEMSIproductCode,
   
 [parameter(Mandatory=$true,ParameterSetName = " File" )]
 [ValidateNotNullOrEmpty()]
 [String]$WEPath,
 
 [parameter(Mandatory=$true,ParameterSetName = " File" )]
 [ValidateNotNullOrEmpty()]
 [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEFileOrFolderName,

 [parameter(Mandatory=$true,ParameterSetName = " File" )]
 [ValidateSet(" notConfigured" ," exists" ," modifiedDate" ," createdDate" ," version" ," sizeInMB" )]
 [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WEFileDetectionType,

 [parameter(Mandatory=$false,ParameterSetName = " File" )]
;  $WEFileDetectionValue = $null,

 [parameter(Mandatory=$true,ParameterSetName = " File" )]
 [ValidateSet(" True" ," False" )]
 [string]$check32BitOn64System = " False" ,

 [parameter(Mandatory=$true,ParameterSetName = " Registry" )]
 [ValidateNotNullOrEmpty()]
 [String]$WERegistryKeyPath,

 [parameter(Mandatory=$true,ParameterSetName = " Registry" )]
 [ValidateSet(" notConfigured" ," exists" ," doesNotExist" ," string" ," integer" ," version" )]
 [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WERegistryDetectionType,

 [parameter(Mandatory=$false,ParameterSetName = " Registry" )]
 [ValidateNotNullOrEmpty()]
 [String]$WERegistryValue,

 [parameter(Mandatory=$true,ParameterSetName = " Registry" )]
 [ValidateSet(" True" ," False" )]
 [string]$check32BitRegOn64System = " False"

)

    if($WEPowerShell){

        if(!(Test-Path " $WEScriptFile" )){
            
            Write-Information Write-WELog " Could not find file '$WEScriptFile'..." " INFO"
            Write-WELog " Script can't continue..." " INFO" -ForegroundColor Red
            Write-Information break

        }
        
       ;  $WEScriptContent = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes(" $WEScriptFile" ));
        
        $WEDR = @{ " @odata.type" = " #microsoft.graph.win32LobAppPowerShellScriptDetection" }
        $WEDR.enforceSignatureCheck = $false;
        $WEDR.runAs32Bit = $false;
        $WEDR.scriptContent =  " $WEScriptContent" ;

    }
    
    elseif($WEMSI){
    
        $WEDR = @{ " @odata.type" = " #microsoft.graph.win32LobAppProductCodeDetection" }
        $WEDR.productVersionOperator = " notConfigured" ;
        $WEDR.productCode = " $WEMsiProductCode" ;
        $WEDR.productVersion =  $null;

    }

    elseif($WEFile){
    
        $WEDR = @{ " @odata.type" = " #microsoft.graph.win32LobAppFileSystemDetection" }
        $WEDR.check32BitOn64System = " $check32BitOn64System" ;
        $WEDR.detectionType = " $WEFileDetectionType" ;
        $WEDR.detectionValue = $WEFileDetectionValue;
        $WEDR.fileOrFolderName = " $WEFileOrFolderName" ;
        $WEDR.operator =  " notConfigured" ;
        $WEDR.path = " $WEPath"

    }

    elseif($WERegistry){
    
        $WEDR = @{ " @odata.type" = " #microsoft.graph.win32LobAppRegistryDetection" }
        $WEDR.check32BitOn64System = " $check32BitRegOn64System" ;
        $WEDR.detectionType = " $WERegistryDetectionType" ;
        $WEDR.detectionValue = "" ;
        $WEDR.keyPath = " $WERegistryKeyPath" ;
        $WEDR.operator = " notConfigured" ;
        $WEDR.valueName = " $WERegistryValue"

    }

    return $WEDR

}



function WE-Get-DefaultReturnCodes(){

@{" returnCode" = 0;" type" = " success" }, `
@{" returnCode" = 1707;" type" = " success" }, `
@{" returnCode" = 3010;" type" = " softReboot" }, `
@{" returnCode" = 1641;" type" = " hardReboot" }, `
@{" returnCode" = 1618;" type" = " retry" }

}



function WE-New-ReturnCode(){

[CmdletBinding()]
$ErrorActionPreference = "Stop"
param(
[parameter(Mandatory=$true)]
[int]$returnCode,
[parameter(Mandatory=$true)]
[ValidateSet('success','softReboot','hardReboot','retry')]
$type
)

    @{" returnCode" = $returnCode;" type" = " $type" }

}



Function Get-IntuneWinXML(){

[CmdletBinding()]
$ErrorActionPreference = "Stop"
param(
[Parameter(Mandatory=$true)]
$WESourceFile,

[Parameter(Mandatory=$true)]
$fileName,

[Parameter(Mandatory=$false)]
[ValidateSet(" false" ," true" )]
[string]$removeitem = " true"
)

Test-SourceFile " $WESourceFile"

$WEDirectory = [System.IO.Path]::GetDirectoryName(" $WESourceFile" )

Add-Type -Assembly System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead(" $WESourceFile" )

    $zip.Entries | where {$_.Name -like " $filename" } | foreach {

    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, " $WEDirectory\$filename" , $true)

    }

$zip.Dispose()

[xml]$WEIntuneWinXML = gc " $WEDirectory\$filename"

return $WEIntuneWinXML

if($removeitem -eq " true" ){ remove-item -ErrorAction Stop " $WEDirectory\$filename" }

}



Function Get-IntuneWinFile(){

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
[Parameter(Mandatory=$true)]
$WESourceFile,

[Parameter(Mandatory=$true)]
$fileName,

[Parameter(Mandatory=$false)]
[string]$WEFolder = " win32"
)

    $WEDirectory = [System.IO.Path]::GetDirectoryName(" $WESourceFile" )

    if(!(Test-Path " $WEDirectory\$folder" )){

        New-Item -ItemType Directory -Path " $WEDirectory" -Name " $folder" | Out-Null

    }

    Add-Type -Assembly System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead(" $WESourceFile" )

        $zip.Entries | where {$_.Name -like " $filename" } | foreach {

        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, " $WEDirectory\$folder\$filename" , $true)

        }

    $zip.Dispose()

    return " $WEDirectory\$folder\$filename"

    if($removeitem -eq " true" ){ remove-item -ErrorAction Stop " $WEDirectory\$filename" }

}



function WE-Upload-Win32Lob(){

<#
.SYNOPSIS
This function is used to upload a Win32 Application to the Intune Service
.DESCRIPTION
This function is used to upload a Win32 Application to the Intune Service
.EXAMPLE
Upload-Win32Lob " C:\Packages\package.intunewin" -publisher " Microsoft" -description " Package"
This example uses all parameters required to add an intunewin File into the Intune Service
.NOTES
NAME: Upload-Win32LOB


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [parameter(Mandatory=$true,Position=1)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$WESourceFile,

    [parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$displayName,

    [parameter(Mandatory=$true,Position=2)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$publisher,

    [parameter(Mandatory=$true,Position=3)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$description,

    [parameter(Mandatory=$true,Position=4)]
    [ValidateNotNullOrEmpty()]
    $detectionRules,

    [parameter(Mandatory=$true,Position=5)]
    [ValidateNotNullOrEmpty()]
    $returnCodes,

    [parameter(Mandatory=$false,Position=6)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$installCmdLine,

    [parameter(Mandatory=$false,Position=7)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$uninstallCmdLine,

    [parameter(Mandatory=$false,Position=8)]
    [ValidateSet('system','user')]
    $installExperience = " system"
)

	try	{

        $WELOBType = " microsoft.graph.win32LobApp"

        Write-WELog " Testing if SourceFile '$WESourceFile' Path is valid..." " INFO" -ForegroundColor Yellow
        Test-SourceFile " $WESourceFile"

        $WEWin32Path = " $WESourceFile"

        Write-Information Write-WELog " Creating JSON data to pass to the service..." " INFO"

        # Funciton to read Win32LOB file
        $WEDetectionXML = Get-IntuneWinXML -ErrorAction Stop " $WESourceFile" -fileName " detection.xml"

        # If displayName input don't use Name from detection.xml file
        if($displayName){ $WEDisplayName = $displayName }
        else { $WEDisplayName = $WEDetectionXML.ApplicationInfo.Name }
        
        $WEFileName = $WEDetectionXML.ApplicationInfo.FileName

        $WESetupFileName = $WEDetectionXML.ApplicationInfo.SetupFile

        $WEExt = [System.IO.Path]::GetExtension($WESetupFileName)

        if((($WEExt).contains(" msi" ) -or ($WEExt).contains(" Msi" )) -and (!$installCmdLine -or !$uninstallCmdLine)){

		    # MSI
           ;  $WEMsiExecutionContext = $WEDetectionXML.ApplicationInfo.MsiInfo.MsiExecutionContext
           ;  $WEMsiPackageType = " DualPurpose" ;
            if($WEMsiExecutionContext -eq " System" ) { $WEMsiPackageType = " PerMachine" }
            elseif($WEMsiExecutionContext -eq " User" ) { $WEMsiPackageType = " PerUser" }

            $WEMsiProductCode = $WEDetectionXML.ApplicationInfo.MsiInfo.MsiProductCode
            $WEMsiProductVersion = $WEDetectionXML.ApplicationInfo.MsiInfo.MsiProductVersion
            $WEMsiPublisher = $WEDetectionXML.ApplicationInfo.MsiInfo.MsiPublisher
            $WEMsiRequiresReboot = $WEDetectionXML.ApplicationInfo.MsiInfo.MsiRequiresReboot
            $WEMsiUpgradeCode = $WEDetectionXML.ApplicationInfo.MsiInfo.MsiUpgradeCode
            
            if($WEMsiRequiresReboot -eq " false" ){ $WEMsiRequiresReboot = $false }
            elseif($WEMsiRequiresReboot -eq " true" ){ $WEMsiRequiresReboot = $true }

            $mobileAppBody = GetWin32AppBody `
                -MSI `
                -displayName " $WEDisplayName" `
                -publisher " $publisher" `
                -description $description `
                -filename $WEFileName `
                -SetupFileName " $WESetupFileName" `
                -installExperience $installExperience `
                -MsiPackageType $WEMsiPackageType `
                -MsiProductCode $WEMsiProductCode `
                -MsiProductName $displayName `
                -MsiProductVersion $WEMsiProductVersion `
                -MsiPublisher $WEMsiPublisher `
                -MsiRequiresReboot $WEMsiRequiresReboot `
                -MsiUpgradeCode $WEMsiUpgradeCode

        }

        else {

           ;  $mobileAppBody = GetWin32AppBody -EXE -displayName " $WEDisplayName" -publisher " $publisher" `
            -description $description -filename $WEFileName -SetupFileName " $WESetupFileName" `
            -installExperience $installExperience -installCommandLine $installCmdLine `
            -uninstallCommandLine $uninstallcmdline

        }

        if($WEDetectionRules.'@odata.type' -contains " #microsoft.graph.win32LobAppPowerShellScriptDetection" -and @($WEDetectionRules).'@odata.type'.Count -gt 1){

            Write-Information Write-Warning " A Detection Rule can either be 'Manually configure detection rules' or 'Use a custom detection script'"
            Write-Warning " It can't include both..."
            Write-Information break

        }

        else {

        $mobileAppBody | Add-Member -MemberType NoteProperty -Name 'detectionRules' -Value $detectionRules

        }

        #ReturnCodes

        if($returnCodes){
        
        $mobileAppBody | Add-Member -MemberType NoteProperty -Name 'returnCodes' -Value @($returnCodes)

        }

        else {

            Write-Information Write-Warning " Intunewin file requires ReturnCodes to be specified"
            Write-Warning " If you want to use the default ReturnCode run 'Get-DefaultReturnCodes'"
            Write-Information break

        }

        Write-Information Write-WELog " Creating application in Intune..." " INFO"
	; 	$mobileApp = MakePostRequest " mobileApps" ($mobileAppBody | ConvertTo-Json);

		# Get the content version for the new app (this will always be 1 until the new app is committed).
        Write-Information Write-WELog " Creating Content Version in the service for the application..." " INFO"
		$appId = $mobileApp.id;
		$contentVersionUri = " mobileApps/$appId/$WELOBType/contentVersions" ;
		$contentVersion = MakePostRequest $contentVersionUri " {}" ;

        # Encrypt file and Get File Information
        Write-Information Write-WELog " Getting Encryption Information for '$WESourceFile'..." " INFO"

        $encryptionInfo = @{};
        $encryptionInfo.encryptionKey = $WEDetectionXML.ApplicationInfo.EncryptionInfo.EncryptionKey
        $encryptionInfo.macKey = $WEDetectionXML.ApplicationInfo.EncryptionInfo.macKey
        $encryptionInfo.initializationVector = $WEDetectionXML.ApplicationInfo.EncryptionInfo.initializationVector
        $encryptionInfo.mac = $WEDetectionXML.ApplicationInfo.EncryptionInfo.mac
        $encryptionInfo.profileIdentifier = " ProfileVersion1" ;
        $encryptionInfo.fileDigest = $WEDetectionXML.ApplicationInfo.EncryptionInfo.fileDigest
        $encryptionInfo.fileDigestAlgorithm = $WEDetectionXML.ApplicationInfo.EncryptionInfo.fileDigestAlgorithm

        $fileEncryptionInfo = @{};
        $fileEncryptionInfo.fileEncryptionInfo = $encryptionInfo;

        # Extracting encrypted file
        $WEIntuneWinFile = Get-IntuneWinFile -ErrorAction Stop " $WESourceFile" -fileName " $filename"

        [int64]$WESize = $WEDetectionXML.ApplicationInfo.UnencryptedContentSize
       ;  $WEEncrySize = (Get-Item -ErrorAction Stop " $WEIntuneWinFile" ).Length

		# Create a new file for the app.
        Write-Information Write-WELog " Creating a new file entry in Azure for the upload..." " INFO"
	; 	$contentVersionId = $contentVersion.id;
		$fileBody = GetAppFileBody " $WEFileName" $WESize $WEEncrySize $null;
		$filesUri = " mobileApps/$appId/$WELOBType/contentVersions/$contentVersionId/files" ;
		$file = MakePostRequest $filesUri ($fileBody | ConvertTo-Json);
	
		# Wait for the service to process the new file request.
        Write-Information Write-WELog " Waiting for the file entry URI to be created..." " INFO"
		$fileId = $file.id;
		$fileUri = " mobileApps/$appId/$WELOBType/contentVersions/$contentVersionId/files/$fileId" ;
		$file = WaitForFileProcessing $fileUri " AzureStorageUriRequest" ;

		# Upload the content to Azure Storage.
        Write-Information Write-WELog " Uploading file to Azure Storage..." " INFO" -f Yellow

		$sasUri = $file.azureStorageUri;
		UploadFileToAzureStorage $file.azureStorageUri " $WEIntuneWinFile" $fileUri;

        # Need to Add removal of IntuneWin file
        $WEIntuneWinFolder = [System.IO.Path]::GetDirectoryName(" $WEIntuneWinFile" )
        Remove-Item -ErrorAction Stop " -Force $WEIntuneWinFile" -Force

		# Commit the file.
        Write-Information Write-WELog " Committing the file into Azure Storage..." " INFO"
	; 	$commitFileUri = " mobileApps/$appId/$WELOBType/contentVersions/$contentVersionId/files/$fileId/commit" ;
		MakePostRequest $commitFileUri ($fileEncryptionInfo | ConvertTo-Json);

		# Wait for the service to process the commit file request.
        Write-Information Write-WELog " Waiting for the service to process the commit file request..." " INFO"
		$file = WaitForFileProcessing $fileUri " CommitFile" ;

		# Commit the app.
        Write-Information Write-WELog " Committing the file into Azure Storage..." " INFO"
		$commitAppUri = " mobileApps/$appId" ;
		$commitAppBody = GetAppCommitBody $contentVersionId $WELOBType;
		MakePatchRequest $commitAppUri ($commitAppBody | ConvertTo-Json);

        Write-WELog " Sleeping for $sleep seconds to allow patch completion..." " INFO" -f Magenta
        Start-Sleep $sleep
        Write-Information }
	
    catch {

		Write-WELog "" " INFO" ;
		Write-Information -ForegroundColor Red " Aborting with exception: $($_.Exception.ToString())" ;
	
    }
}



Function Test-AuthToken(){

    # Checking if authToken exists before running authentication
    if($global:authToken){

        # Setting DateTime to Universal time to work in all timezones
        $WEDateTime = (Get-Date).ToUniversalTime()

        # If the authToken exists checking when it expires
        $WETokenExpires = ($authToken.ExpiresOn.datetime - $WEDateTime).Minutes

            if($WETokenExpires -le 0){

            Write-Information " Authentication Token expired" $WETokenExpires " minutes ago" -ForegroundColor Yellow
            Write-Information # Defining Azure AD tenant name, this is the name of your Azure Active Directory (do not use the verified domain name)

                if($null -eq $WEUser -or $WEUser -eq "" ){

                $WEGlobal:User = Read-Host -Prompt " Please specify your user principal name for Azure Authentication"
                Write-Information }

            $script:authToken = Get-AuthToken -User $WEUser

            }
    }

    # Authentication doesn't exist, calling Get-AuthToken -ErrorAction Stop [CmdletBinding()]
function

    else {

        if($null -eq $WEUser -or $WEUser -eq "" ){

            $WEGlobal:User = Read-Host -Prompt " Please specify your user principal name for Azure Authentication"
            Write-Information }

    # Getting the authorization token
    $script:authToken = Get-AuthToken -User $WEUser

    }
}



Test-AuthToken


; 
$baseUrl = " https://graph.microsoft.com/beta/deviceAppManagement/"
; 
$logRequestUris = $true;
$logHeaders = $false;
$logContent = $true;

$azureStorageUploadChunkSizeInMb = 6l;

$sleep = 30



$WESourceFile = " C:\packages\package.intunewin"


$WEDetectionXML = Get-IntuneWinXML -ErrorAction Stop " $WESourceFile" -fileName " detection.xml"


$WEFileRule = New-DetectionRule -File -Path " C:\Program Files\Application" `
-FileOrFolderName " application.exe" -FileDetectionType exists -check32BitOn64System False

$WERegistryRule = New-DetectionRule -Registry -RegistryKeyPath " HKEY_LOCAL_MACHINE\SOFTWARE\Program" `
-RegistryDetectionType exists -check32BitRegOn64System True

$WEMSIRule = New-DetectionRule -MSI -MSIproductCode $WEDetectionXML.ApplicationInfo.MsiInfo.MsiProductCode

; 
$WEDetectionRule = @($WEFileRule,$WERegistryRule,$WEMSIRule)
; 
$WEReturnCodes = Get-DefaultReturnCodes -ErrorAction Stop

$WEReturnCodes = $WEReturnCodes + New-ReturnCode -returnCode 302 -type softReboot; 
$WEReturnCodes = $WEReturnCodes + New-ReturnCode -returnCode 145 -type hardReboot


Upload-Win32Lob -SourceFile " $WESourceFile" -publisher " Publisher" `
-description " Description" -detectionRules $WEDetectionRule -returnCodes $WEReturnCodes `
-installCmdLine " powershell.exe .\install.ps1" `
-uninstallCmdLine " powershell.exe .\uninstall.ps1"





# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================