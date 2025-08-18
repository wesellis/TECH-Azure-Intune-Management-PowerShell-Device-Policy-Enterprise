<#
.SYNOPSIS
    Application Lob Add

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
    We Enhanced Application Lob Add

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



function WE-UploadFileToAzureStorage($sasUri, $filepath){

	# Chunk size = 1 MiB
    $chunkSizeInBytes = 1024 * 1024;

	# Read the whole file and find the total chunks.
	#[byte[]]$bytes = Get-Content -ErrorAction Stop $filepath -Encoding byte;
    # Using ReadAllBytes method as the Get-Content -ErrorAction Stop used alot of memory on the machine
    [byte[]]$bytes = [System.IO.File]::ReadAllBytes($filepath);
	$chunks = [Math]::Ceiling($bytes.Length / $chunkSizeInBytes);

	# Upload each chunk.
	$ids = @();
    $cc = 1

	for ($chunk = 0; $chunk -lt $chunks; $chunk++)
	{
        $id = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($chunk.ToString(" 0000" )));
		$ids = $ids + $id;

		$start = $chunk * $chunkSizeInBytes;
		$end = [Math]::Min($start + $chunkSizeInBytes - 1, $bytes.Length - 1);
		$body = $bytes[$start..$end];

        Write-Progress -Activity " Uploading File to Azure Storage" -status " Uploading chunk $cc of $chunks" `
        -percentComplete ($cc / $chunks*100)
        $cc++

        $uploadResponse = UploadAzureStorageChunk $sasUri $id $body;


	}

    Write-Progress -Completed -Activity " Uploading File to Azure Storage"

    Write-Information # Finalize the upload.
	$uploadResponse = FinalizeAzureStorageUpload $sasUri $ids;
}



[CmdletBinding()]
function WE-GenerateKey{

	try
	{
		$aes = [System.Security.Cryptography.Aes]::Create();
        $aesProvider = New-Object -ErrorAction Stop System.Security.Cryptography.AesCryptoServiceProvider;
        $aesProvider.GenerateKey();
        $aesProvider.Key;
	}
	finally
	{
		if ($null -ne $aesProvider) { $aesProvider.Dispose(); }
		if ($null -ne $aes) { $aes.Dispose(); }
	}
}



[CmdletBinding()]
function WE-GenerateIV{

	try
	{
		$aes = [System.Security.Cryptography.Aes]::Create();
        $aes.IV;
	}
	finally
	{
		if ($null -ne $aes) { $aes.Dispose(); }
	}
}



function WE-EncryptFileWithIV($sourceFile, $targetFile, $encryptionKey, $hmacKey, $initializationVector){

	$bufferBlockSize = 1024 * 4;
	$computedMac = $null;

	try
	{
		$aes = [System.Security.Cryptography.Aes]::Create();
		$hmacSha256 = New-Object -ErrorAction Stop System.Security.Cryptography.HMACSHA256;
		$hmacSha256.Key = $hmacKey;
		$hmacLength = $hmacSha256.HashSize / 8;

		$buffer = New-Object -ErrorAction Stop byte[] $bufferBlockSize;
		$bytesRead = 0;

		$targetStream = [System.IO.File]::Open($targetFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read);
		$targetStream.Write($buffer, 0, $hmacLength + $initializationVector.Length);

		try
		{
			$encryptor = $aes.CreateEncryptor($encryptionKey, $initializationVector);
			$sourceStream = [System.IO.File]::Open($sourceFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read);
			$cryptoStream = New-Object -ErrorAction Stop System.Security.Cryptography.CryptoStream -ArgumentList @($targetStream, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write);

			$targetStream = $null;
			while (($bytesRead = $sourceStream.Read($buffer, 0, $bufferBlockSize)) -gt 0)
			{
				$cryptoStream.Write($buffer, 0, $bytesRead);
				$cryptoStream.Flush();
			}
			$cryptoStream.FlushFinalBlock();
		}
		finally
		{
			if ($null -ne $cryptoStream) { $cryptoStream.Dispose(); }
			if ($null -ne $sourceStream) { $sourceStream.Dispose(); }
			if ($null -ne $encryptor) { $encryptor.Dispose(); }	
		}

		try
		{
			$finalStream = [System.IO.File]::Open($targetFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::Read)

			$finalStream.Seek($hmacLength, [System.IO.SeekOrigin]::Begin) > $null;
			$finalStream.Write($initializationVector, 0, $initializationVector.Length);
			$finalStream.Seek($hmacLength, [System.IO.SeekOrigin]::Begin) > $null;

			$hmac = $hmacSha256.ComputeHash($finalStream);
			$computedMac = $hmac;

			$finalStream.Seek(0, [System.IO.SeekOrigin]::Begin) > $null;
			$finalStream.Write($hmac, 0, $hmac.Length);
		}
		finally
		{
			if ($null -ne $finalStream) { $finalStream.Dispose(); }
		}
	}
	finally
	{
		if ($null -ne $targetStream) { $targetStream.Dispose(); }
        if ($null -ne $aes) { $aes.Dispose(); }
	}

	$computedMac;
}



function WE-EncryptFile($sourceFile, $targetFile){

	$encryptionKey = GenerateKey;
	$hmacKey = GenerateKey;
	$initializationVector = GenerateIV;

	# Create the encrypted target file and compute the HMAC value.
	$mac = EncryptFileWithIV $sourceFile $targetFile $encryptionKey $hmacKey $initializationVector;

	# Compute the SHA256 hash of the source file and convert the result to bytes.
	$fileDigest = (Get-FileHash -ErrorAction Stop $sourceFile -Algorithm SHA256).Hash;
	$fileDigestBytes = New-Object -ErrorAction Stop byte[] ($fileDigest.Length / 2);
    for ($i = 0; $i -lt $fileDigest.Length; $i = $i + 2)
	{
        $fileDigestBytes[$i / 2] = [System.Convert]::ToByte($fileDigest.Substring($i, 2), 16);
    }
	
	# Return an object that will serialize correctly to the file commit Graph API.
	$encryptionInfo = @{};
	$encryptionInfo.encryptionKey = [System.Convert]::ToBase64String($encryptionKey);
	$encryptionInfo.macKey = [System.Convert]::ToBase64String($hmacKey);
	$encryptionInfo.initializationVector = [System.Convert]::ToBase64String($initializationVector);
	$encryptionInfo.mac = [System.Convert]::ToBase64String($mac);
	$encryptionInfo.profileIdentifier = " ProfileVersion1" ;
	$encryptionInfo.fileDigest = [System.Convert]::ToBase64String($fileDigestBytes);
	$encryptionInfo.fileDigestAlgorithm = " SHA256" ;

	$fileEncryptionInfo = @{};
	$fileEncryptionInfo.fileEncryptionInfo = $encryptionInfo;

	$fileEncryptionInfo;

}



function WE-WaitForFileProcessing($fileUri, $stage){

	$attempts= 60;
	$waitTimeInSeconds = 1;

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
			throw " File upload state is not success: $($file.uploadState)" ;
		}

		Start-Sleep $waitTimeInSeconds;
		$attempts--;
	}

	if ($null -eq $file)
	{
		throw " File request did not complete in the allotted time." ;
	}

	$file;

}



function WE-GetAndroidAppBody($displayName, $publisher, $description, $filename, $identityName, $identityVersion, $versionName, $minimumSupportedOperatingSystem){

	$body = @{ " @odata.type" = " #microsoft.graph.androidLOBApp" };
	$body.categories = @();
	$body.displayName = $displayName;
	$body.publisher = $publisher;
	$body.description = $description;
	$body.fileName = $filename;
	$body.identityName = $identityName;
	$body.identityVersion = $identityVersion;
	
    if ($null -eq $minimumSupportedOperatingSystem){

		$body.minimumSupportedOperatingSystem = @{ " v4_4" = $true };
	
    }
	
    else {

		$body.minimumSupportedOperatingSystem = $minimumSupportedOperatingSystem;
	
    }

	$body.informationUrl = $null;
	$body.isFeatured = $false;
	$body.privacyInformationUrl = $null;
	$body.developer = "" ;
	$body.notes = "" ;
	$body.owner = "" ;
    $body.versionCode = $identityVersion;
    $body.versionName = $versionName;

	$body;
}



function WE-GetiOSAppBody($displayName, $publisher, $description, $filename, $bundleId, $identityVersion, $versionNumber, $expirationDateTime){

	$body = @{ " @odata.type" = " #microsoft.graph.iosLOBApp" };
    $body.applicableDeviceType = @{ " iPad" = $true; " iPhoneAndIPod" = $true }
	$body.categories = @();
	$body.displayName = $displayName;
	$body.publisher = $publisher;
	$body.description = $description;
	$body.fileName = $filename;
	$body.bundleId = $bundleId;
	$body.identityVersion = $identityVersion;
	if ($null -eq $minimumSupportedOperatingSystem)
	{
		$body.minimumSupportedOperatingSystem = @{ " v9_0" = $true };
	}
	else
	{
		$body.minimumSupportedOperatingSystem = $minimumSupportedOperatingSystem;
	}

	$body.informationUrl = $null;
	$body.isFeatured = $false;
	$body.privacyInformationUrl = $null;
	$body.developer = "" ;
	$body.notes = "" ;
	$body.owner = "" ;
    $body.expirationDateTime = $expirationDateTime;
    $body.versionNumber = $versionNumber;

	$body;
}



function WE-GetMSIAppBody($displayName, $publisher, $description, $filename, $identityVersion, $WEProductCode){

	$body = @{ " @odata.type" = " #microsoft.graph.windowsMobileMSI" };
	$body.displayName = $displayName;
	$body.publisher = $publisher;
	$body.description = $description;
	$body.fileName = $filename;
	$body.identityVersion = $identityVersion;
	$body.informationUrl = $null;
	$body.isFeatured = $false;
	$body.privacyInformationUrl = $null;
	$body.developer = "" ; 
	$body.notes = "" ;
	$body.owner = "" ;
    $body.productCode = " $WEProductCode" ;
    $body.productVersion = " $identityVersion" ;

	$body;
}



function WE-GetAppFileBody($name, $size, $sizeEncrypted, $manifest){

	$body = @{ " @odata.type" = " #microsoft.graph.mobileAppContentFile" };
	$body.name = $name;
	$body.size = $size;
	$body.sizeEncrypted = $sizeEncrypted;
	$body.manifest = $manifest;

	$body;
}



function WE-GetAppCommitBody($contentVersionId, $WELobType){

	$body = @{ " @odata.type" = " #$WELobType" };
	$body.committedContentVersion = $contentVersionId;

	$body;

}



Function Get-MSIFileInformation(){



[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [System.IO.FileInfo]$WEPath,
 
    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [ValidateSet(" ProductCode" , " ProductVersion" , " ProductName" , " Manufacturer" , " ProductLanguage" , " FullVersion" )]
    [string]$WEProperty
)
Process {

    try {
        # Read property from MSI database
        $WEWindowsInstaller = New-Object -ComObject WindowsInstaller.Installer
        $WEMSIDatabase = $WEWindowsInstaller.GetType().InvokeMember(" OpenDatabase" , " InvokeMethod" , $null, $WEWindowsInstaller, @($WEPath.FullName, 0))
        $WEQuery = " SELECT Value FROM Property WHERE Property = '$($WEProperty)'"
        $WEView = $WEMSIDatabase.GetType().InvokeMember(" OpenView" , " InvokeMethod" , $null, $WEMSIDatabase, ($WEQuery))
        $WEView.GetType().InvokeMember(" Execute" , " InvokeMethod" , $null, $WEView, $null)
        $WERecord = $WEView.GetType().InvokeMember(" Fetch" , " InvokeMethod" , $null, $WEView, $null)
        $WEValue = $WERecord.GetType().InvokeMember(" StringData" , " GetProperty" , $null, $WERecord, 1)
 
        # Commit database and close view
        $WEMSIDatabase.GetType().InvokeMember(" Commit" , " InvokeMethod" , $null, $WEMSIDatabase, $null)
        $WEView.GetType().InvokeMember(" Close" , " InvokeMethod" , $null, $WEView, $null)           
       ;  $WEMSIDatabase = $null
       ;  $WEView = $null
 
        # Return the value
        return $WEValue
    }

    catch {

        Write-Warning -Message $_.Exception.Message;
        break;
    
    }

}

    End {
        # Run garbage collection and release ComObject
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($WEWindowsInstaller) | Out-Null
        [System.GC]::Collect()
    }

}



Function Test-SourceFile(){

[CmdletBinding()]
$ErrorActionPreference = "Stop"
param(
    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    $WESourceFile
)

    try {

            if(!(test-path " $WESourceFile" )){

            Write-WELog " Source File '$sourceFile' doesn't exist..." " INFO" -ForegroundColor Red
            throw

            }

        }

    catch {

		Write-Information -ForegroundColor Red $_.Exception.Message;
        Write-Information break;

    }

}



[CmdletBinding()]
Function Get-ApkInformation -ErrorAction Stop {

<#
.SYNOPSIS
This function is used to get information about an Android APK file using the Android SDK - https://developer.android.com/studio/index.html
.DESCRIPTION
This function is used to get information about an Android APK file using the Android SDK - https://developer.android.com/studio/index.html
.EXAMPLE
Get-ApkInformation -sourceFile c:\source\application.apk
Function will return two object, object[0] is the identityName and object[1] is the identityVersion
.NOTES
NAME: Get-ApkInformation -ErrorAction Stop


[cmdletbinding()]

[CmdletBinding()]
$ErrorActionPreference = " Stop"
param(
    [Parameter(Mandatory=$true)]
    $sourceFile,
    [Parameter(Mandatory=$true)]
    $WEAndroidSDK
)

    if(!(test-path $WEAndroidSDK)){

    Write-Information Write-WELog " Android SDK isn't installed..." " INFO"
    Write-WELog " Please install Android Studio and install the SDK from https://developer.android.com/studio/index.html" " INFO"
    Write-Information break

    }

    if(((gci $WEAndroidSDK | select name).Name).count -gt 1){

    $WEBuildTools = ((gci $WEAndroidSDK | select name).Name | sort -Descending)[0]

    }

    else {

    $WEBuildTools = ((gci $WEAndroidSDK | select name).Name)

    }

$aaptPath = " $WEAndroidSDK\$WEBuildTools"

[ScriptBlock]$command = {

    cmd.exe /c " $aaptPath\aapt.exe" dump badging " $sourceFile"

}

$aaptRun = Invoke-Command -ScriptBlock $command
; 
$WEAndroidPackage = $aaptRun | ? { ($_).startswith(" package" ) }
; 
$WEPackageInfo = $WEAndroidPackage.split(" " )

$WEPackageInfo[1].Split(" '" )[1]
$WEPackageInfo[2].Split(" '" )[1]
$WEPackageInfo[3].Split(" '" )[1]

if ($logContent) { Write-Information -ForegroundColor Gray $WEPackageInfo[1].Split(" '" )[1]; }
if ($logContent) { Write-Information -ForegroundColor Gray $WEPackageInfo[2].Split(" '" )[1]; }
if ($logContent) { Write-Information -ForegroundColor Gray $WEPackageInfo[3].Split(" '" )[1]; }

}



function WE-Upload-AndroidLob(){

<#
.SYNOPSIS
This function is used to upload an Android LOB Application to the Intune Service
.DESCRIPTION
This function is used to upload an Android LOB Application to the Intune Service
.EXAMPLE
Upload-AndroidLob -sourceFile " C:\Software\package.apk" -publisher " Publisher Name" -description " Description of Application" -identityName " com.package" -identityVersion " 1" -versionName " 10.1.1"
This example uses all parameters required to add an Android Application into the Intune Service
Upload-AndroidLob -sourceFile " C:\Software\package.apk" -publisher " Publisher Name" -description " Description of Application"
This example uses the required parameters to add an Android Application into the Intune Service. This example will require the Android SDK to get identityName and identityVersion
.NOTES
NAME: Upload-AndroidLOB


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

    [parameter(Mandatory=$false)]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$identityName,

    [parameter(Mandatory=$false)]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$identityVersion,

    [parameter(Mandatory=$false)]
    [string]$versionName

)

	try
	{
		
        $WELOBType = " microsoft.graph.androidLOBApp"

        Write-WELog " Testing if SourceFile '$WESourceFile' Path is valid..." " INFO" -ForegroundColor Yellow
        Test-SourceFile " $WESourceFile"

            if(!$identityName){

            Write-Information Write-WELog " Opening APK file to get identityName to pass to the service..." " INFO"

            $WEAPKInformation = Get-ApkInformation -AndroidSDK $WEAndroidSDKLocation -sourceFile " $WESourceFile"

            $identityName = $WEAPKInformation[0]

            }

            if(!$identityVersion){

            Write-Information Write-WELog " Opening APK file to get identityVersion to pass to the service..." " INFO"

            $WEAPKInformation = Get-ApkInformation -AndroidSDK $WEAndroidSDKLocation -sourceFile " $WESourceFile"

            $identityVersion = $WEAPKInformation[1]

            }

            if(!$versionName){

            Write-Information Write-WELog " Opening APK file to get versionName to pass to the service..." " INFO"

            $WEAPKInformation = Get-ApkInformation -AndroidSDK $WEAndroidSDKLocation -sourceFile " $WESourceFile"

            $versionName = $WEAPKInformation[2]

            }


        # Creating temp file name from Source File path
        $tempFile = [System.IO.Path]::GetDirectoryName(" $WESourceFile" ) + " \" + [System.IO.Path]::GetFileNameWithoutExtension(" $WESourceFile" ) + " _temp.bin"

        # Creating filename variable from Source File Path
        $filename = [System.IO.Path]::GetFileName(" $WESourceFile" )

            if(!($displayName)){

           ;  $displayName = $filename

            }

        # Create a new Android LOB app.
        Write-Information Write-WELog " Creating JSON data to pass to the service..." " INFO"
	; 	$mobileAppBody = GetAndroidAppBody " $displayName" " $WEPublisher" " $WEDescription" " $filename" " $identityName" " $identityVersion" " $versionName" ;
		
        Write-Information Write-WELog " Creating application in Intune..." " INFO"
        $mobileApp = MakePostRequest " mobileApps" ($mobileAppBody | ConvertTo-Json);

		# Get the content version for the new app (this will always be 1 until the new app is committed).
        Write-Information Write-WELog " Creating Content Version in the service for the application..." " INFO"
		$appId = $mobileApp.id;
		$contentVersionUri = " mobileApps/$appId/$WELOBType/contentVersions" ;
		$contentVersion = MakePostRequest $contentVersionUri " {}" ;

        # Encrypt file and Get File Information
        Write-Information Write-WELog " Ecrypting the file '$WESourceFile'..." " INFO"
        $encryptionInfo = EncryptFile " $sourceFile" " $tempFile" ;
        $WESize = (Get-Item -ErrorAction Stop " $sourceFile" ).Length
        $WEEncrySize = (Get-Item -ErrorAction Stop " $tempFile" ).Length

        Write-Information Write-WELog " Creating the manifest file used to install the application on the device..." " INFO"

        [xml]$manifestXML = '<?xml version=" 1.0" encoding=" utf-8" ?><AndroidManifestProperties xmlns:xsd=" http://www.w3.org/2001/XMLSchema" xmlns:xsi=" http://www.w3.org/2001/XMLSchema-instance" ><Package>com.leadapps.android.radio.ncp</Package><PackageVersionCode>10</PackageVersionCode><PackageVersionName>1.0.5.4</PackageVersionName><ApplicationName>A_Online_Radio_1.0.5.4.apk</ApplicationName><MinSdkVersion>3</MinSdkVersion><AWTVersion></AWTVersion></AndroidManifestProperties>'

        $manifestXML.AndroidManifestProperties.Package = " $identityName" # com.application.test
        $manifestXML.AndroidManifestProperties.PackageVersionCode = " $identityVersion" # 10
        $manifestXML.AndroidManifestProperties.PackageVersionName = " $identityVersion" # 1.0.5.4
        $manifestXML.AndroidManifestProperties.ApplicationName = " $filename" # name.apk

        $manifestXML_Output = $manifestXML.OuterXml.ToString()

        $WEBytes = [System.Text.Encoding]::ASCII.GetBytes($manifestXML_Output)
       ;  $WEEncodedText =[Convert]::ToBase64String($WEBytes)

		# Create a new file for the app.
        Write-Information Write-WELog " Creating a new file entry in Azure for the upload..." " INFO"
	; 	$contentVersionId = $contentVersion.id;
		$fileBody = GetAppFileBody " $filename" $WESize $WEEncrySize " $WEEncodedText" ;
		$filesUri = " mobileApps/$appId/$WELOBType/contentVersions/$contentVersionId/files" ;
		$file = MakePostRequest $filesUri ($fileBody | ConvertTo-Json);
	
		# Wait for the service to process the new file request.
        Write-Information Write-WELog " Waiting for the file entry URI to be created..." " INFO"
		$fileId = $file.id;
		$fileUri = " mobileApps/$appId/$WELOBType/contentVersions/$contentVersionId/files/$fileId" ;
		$file = WaitForFileProcessing $fileUri " AzureStorageUriRequest" ;

        # Upload the content to Azure Storage.
        Write-Information Write-WELog " Uploading file to Azure Storage URI..." " INFO"
		
        $sasUri = $file.azureStorageUri;
		UploadFileToAzureStorage $file.azureStorageUri $tempFile;

		# Commit the file.
        Write-Information Write-WELog " Committing the file into Azure Storage..." " INFO"
		$commitFileUri = " mobileApps/$appId/$WELOBType/contentVersions/$contentVersionId/files/$fileId/commit" ;
		MakePostRequest $commitFileUri ($encryptionInfo | ConvertTo-Json);

		# Wait for the service to process the commit file request.
        Write-Information Write-WELog " Waiting for the service to process the commit file request..." " INFO"
		$file = WaitForFileProcessing $fileUri " CommitFile" ;

		# Commit the app.
        Write-Information Write-WELog " Committing the application to the Intune Service..." " INFO"
		$commitAppUri = " mobileApps/$appId" ;
		$commitAppBody = GetAppCommitBody $contentVersionId $WELOBType;
		MakePatchRequest $commitAppUri ($commitAppBody | ConvertTo-Json);

        Write-WELog " Removing Temporary file '$tempFile'..." " INFO" -f Gray
        Remove-Item -Path " $tempFile" -Force
        Write-Information Write-WELog " Sleeping for $sleep seconds to allow patch completion..." " INFO" -f Magenta
        Start-Sleep $sleep
        Write-Information }
	catch
	{
		Write-WELog "" " INFO" ;
		Write-Information -ForegroundColor Red " Aborting with exception: $($_.Exception.ToString())" ;
	}
}



function WE-Upload-iOSLob(){

<#
.SYNOPSIS
This function is used to upload an iOS LOB Application to the Intune Service
.DESCRIPTION
This function is used to upload an iOS LOB Application to the Intune Service
.EXAMPLE
Upload-iOSLob -sourceFile " C:\Software\package.ipa" -displayName " package.ipa" -publisher " Publisher Name" -description " Description of Application" -bundleId " com.package" -identityVersion " 1" -versionNumber " 3.0.0" -expirationDateTime " 2018-02-14T20:53:52Z"
This example uses all parameters required to add an iOS Application into the Intune Service
.NOTES
NAME: Upload-iOSLOB


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

    [parameter(Mandatory=$true,Position=2)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$displayName,

    [parameter(Mandatory=$true,Position=3)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$publisher,

    [parameter(Mandatory=$true,Position=4)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$description,

    [parameter(Mandatory=$true,Position=5)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$bundleId,

    [parameter(Mandatory=$true,Position=6)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$identityVersion,

    [parameter(Mandatory=$true,Position=7)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$versionNumber,

    [parameter(Mandatory=$true,Position=8)]
    [ValidateNotNullOrEmpty()]
    [string]$expirationDateTime
)

	try
	{
		
        $WELOBType = " microsoft.graph.iosLOBApp"

        Write-WELog " Testing if SourceFile '$WESourceFile' Path is valid..." " INFO" -ForegroundColor Yellow
        Test-SourceFile " $WESourceFile"

        # Checking expirationdatetime of SourceFile to check if it can be uploaded
        [datetimeoffset]$WEExpiration = $expirationDateTime

        $WEDate = get-date -ErrorAction Stop

            if($WEExpiration -lt $WEDate){

                Write-Error " $WESourceFile has expired Follow the guidelines provided by Apple to extend the expiration date, then try adding the app again"
                throw

            }

        # Creating temp file name from Source File path
        $tempFile = [System.IO.Path]::GetDirectoryName(" $WESourceFile" ) + " \" + [System.IO.Path]::GetFileNameWithoutExtension(" $WESourceFile" ) + " _temp.bin"
        
        # Creating filename variable from Source File Path
       ;  $filename = [System.IO.Path]::GetFileName(" $WESourceFile" )

        # Create a new iOS LOB app.
        Write-Information Write-WELog " Creating JSON data to pass to the service..." " INFO"
	; 	$mobileAppBody = GetiOSAppBody " $displayName" " $WEPublisher" " $WEDescription" " $filename" " $bundleId" " $identityVersion" " $versionNumber" " $expirationDateTime" ;

        Write-Information Write-WELog " Creating application in Intune..." " INFO"

		$mobileApp = MakePostRequest " mobileApps" ($mobileAppBody | ConvertTo-Json);

		# Get the content version for the new app (this will always be 1 until the new app is committed).
        Write-Information Write-WELog " Creating Content Version in the service for the application..." " INFO"
		$appId = $mobileApp.id;
		$contentVersionUri = " mobileApps/$appId/$WELOBType/contentVersions" ;
		$contentVersion = MakePostRequest $contentVersionUri " {}" ;

        # Encrypt file and Get File Information
        Write-Information Write-WELog " Ecrypting the file '$WESourceFile'..." " INFO"
        $encryptionInfo = EncryptFile $sourceFile $tempFile;
        $WESize = (Get-Item -ErrorAction Stop " $sourceFile" ).Length
        $WEEncrySize = (Get-Item -ErrorAction Stop " $tempFile" ).Length

        Write-Information Write-WELog " Creating the manifest file used to install the application on the device..." " INFO"

        [string]$manifestXML = '<?xml version=" 1.0" encoding=" UTF-8" ?><!DOCTYPE plist PUBLIC " -//Apple//DTD PLIST 1.0//EN" " http://www.apple.com/DTDs/PropertyList-1.0.dtd" ><plist version=" 1.0" ><dict><key>items</key><array><dict><key>assets</key><array><dict><key>kind</key><string>software-package</string><key>url</key><string>{UrlPlaceHolder}</string></dict></array><key>metadata</key><dict><key>AppRestrictionPolicyTemplate</key> <string>http://management.microsoft.com/PolicyTemplates/AppRestrictions/iOS/v1</string><key>AppRestrictionTechnology</key><string>Windows Intune Application Restrictions Technology for iOS</string><key>IntuneMAMVersion</key><string></string><key>CFBundleSupportedPlatforms</key><array><string>iPhoneOS</string></array><key>MinimumOSVersion</key><string>9.0</string><key>bundle-identifier</key><string>bundleid</string><key>bundle-version</key><string>bundleversion</string><key>kind</key><string>software</string><key>subtitle</key><string>LaunchMeSubtitle</string><key>title</key><string>bundletitle</string></dict></dict></array></dict></plist>'

        $manifestXML = $manifestXML.replace(" bundleid" ," $bundleId" )
        $manifestXML = $manifestXML.replace(" bundleversion" ," $identityVersion" )
        $manifestXML = $manifestXML.replace(" bundletitle" ," $displayName" )

        $WEBytes = [System.Text.Encoding]::ASCII.GetBytes($manifestXML)
       ;  $WEEncodedText =[Convert]::ToBase64String($WEBytes)

		# Create a new file for the app.
        Write-Information Write-WELog " Creating a new file entry in Azure for the upload..." " INFO"
	; 	$contentVersionId = $contentVersion.id;
		$fileBody = GetAppFileBody " $filename" $WESize $WEEncrySize " $WEEncodedText" ;
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
		UploadFileToAzureStorage $file.azureStorageUri $tempFile;

		# Commit the file.
        Write-Information Write-WELog " Committing the file into Azure Storage..." " INFO"
		$commitFileUri = " mobileApps/$appId/$WELOBType/contentVersions/$contentVersionId/files/$fileId/commit" ;
		MakePostRequest $commitFileUri ($encryptionInfo | ConvertTo-Json);

		# Wait for the service to process the commit file request.
        Write-Information Write-WELog " Waiting for the service to process the commit file request..." " INFO"
		$file = WaitForFileProcessing $fileUri " CommitFile" ;

		# Commit the app.
        Write-Information Write-WELog " Committing the file into Azure Storage..." " INFO"
		$commitAppUri = " mobileApps/$appId" ;
		$commitAppBody = GetAppCommitBody $contentVersionId $WELOBType;
		MakePatchRequest $commitAppUri ($commitAppBody | ConvertTo-Json);

        Write-WELog " Removing Temporary file '$tempFile'..." " INFO" -f Gray
        Remove-Item -Path " $tempFile" -Force
        Write-Information Write-WELog " Sleeping for $sleep seconds to allow patch completion..." " INFO" -f Magenta
        Start-Sleep $sleep
        Write-Information }
	catch
	{
		Write-WELog "" " INFO" ;
		Write-Information -ForegroundColor Red " Aborting with exception: $($_.Exception.ToString())" ;
	}
}



function WE-Upload-MSILob(){

<#
.SYNOPSIS
This function is used to upload an MSI LOB Application to the Intune Service
.DESCRIPTION
This function is used to upload an MSI LOB Application to the Intune Service
.EXAMPLE
Upload-MSILob " C:\Software\Orca\Orca.Msi" -publisher " Microsoft" -description " Orca"
This example uses all parameters required to add an MSI Application into the Intune Service
.NOTES
NAME: Upload-MSILOB


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

    [parameter(Mandatory=$true,Position=2)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$publisher,

    [parameter(Mandatory=$true,Position=3)]
    [ValidateNotNullOrEmpty()]
    [string]$description
)

	try	{

        $WELOBType = " microsoft.graph.windowsMobileMSI"

        Write-WELog " Testing if SourceFile '$WESourceFile' Path is valid..." " INFO" -ForegroundColor Yellow
        Test-SourceFile " $WESourceFile"

        $WEMSIPath = " $WESourceFile"

        # Creating temp file name from Source File path
        $tempFile = [System.IO.Path]::GetDirectoryName(" $WESourceFile" ) + " \" + [System.IO.Path]::GetFileNameWithoutExtension(" $WESourceFile" ) + " _temp.bin"

        Write-Information Write-WELog " Creating JSON data to pass to the service..." " INFO"

        $WEFileName = [System.IO.Path]::GetFileName(" $WEMSIPath" )

        $WEPN = (Get-MSIFileInformation -Path " $WEMSIPath" -Property ProductName | Out-String).trimend()
        $WEPC = (Get-MSIFileInformation -Path " $WEMSIPath" -Property ProductCode | Out-String).trimend()
        $WEPV = (Get-MSIFileInformation -Path " $WEMSIPath" -Property ProductVersion | Out-String).trimend()
        $WEPL = (Get-MSIFileInformation -Path " $WEMSIPath" -Property ProductLanguage | Out-String).trimend()

		# Create a new MSI LOB app.
	; 	$mobileAppBody = GetMSIAppBody -displayName " $WEPN" -publisher " $publisher" -description " $description" -filename " $WEFileName" -identityVersion " $WEPV" -ProductCode " $WEPC"
        
        Write-Information Write-WELog " Creating application in Intune..." " INFO"
	; 	$mobileApp = MakePostRequest " mobileApps" ($mobileAppBody | ConvertTo-Json);

		# Get the content version for the new app (this will always be 1 until the new app is committed).
        Write-Information Write-WELog " Creating Content Version in the service for the application..." " INFO"
		$appId = $mobileApp.id;
		$contentVersionUri = " mobileApps/$appId/$WELOBType/contentVersions" ;
		$contentVersion = MakePostRequest $contentVersionUri " {}" ;

        # Encrypt file and Get File Information
        Write-Information Write-WELog " Ecrypting the file '$WESourceFile'..." " INFO"
        $encryptionInfo = EncryptFile $sourceFile $tempFile;
        $WESize = (Get-Item -ErrorAction Stop " $sourceFile" ).Length
        $WEEncrySize = (Get-Item -ErrorAction Stop " $tempFile" ).Length

        Write-Information Write-WELog " Creating the manifest file used to install the application on the device..." " INFO"

        [xml]$manifestXML = '<MobileMsiData MsiExecutionContext=" Any" MsiRequiresReboot=" false" MsiUpgradeCode="" MsiIsMachineInstall=" true" MsiIsUserInstall=" false" MsiIncludesServices=" false" MsiContainsSystemRegistryKeys=" false" MsiContainsSystemFolders=" false" ></MobileMsiData>'

        $manifestXML.MobileMsiData.MsiUpgradeCode = " $WEPC"

        $manifestXML_Output = $manifestXML.OuterXml.ToString()

        $WEBytes = [System.Text.Encoding]::ASCII.GetBytes($manifestXML_Output)
       ;  $WEEncodedText =[Convert]::ToBase64String($WEBytes)

		# Create a new file for the app.
        Write-Information Write-WELog " Creating a new file entry in Azure for the upload..." " INFO"
	; 	$contentVersionId = $contentVersion.id;
		$fileBody = GetAppFileBody " $WEFileName" $WESize $WEEncrySize " $WEEncodedText" ;
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
		UploadFileToAzureStorage $file.azureStorageUri $tempFile;

		# Commit the file.
        Write-Information Write-WELog " Committing the file into Azure Storage..." " INFO"
		$commitFileUri = " mobileApps/$appId/$WELOBType/contentVersions/$contentVersionId/files/$fileId/commit" ;
		MakePostRequest $commitFileUri ($encryptionInfo | ConvertTo-Json);

		# Wait for the service to process the commit file request.
        Write-Information Write-WELog " Waiting for the service to process the commit file request..." " INFO"
		$file = WaitForFileProcessing $fileUri " CommitFile" ;

		# Commit the app.
        Write-Information Write-WELog " Committing the file into Azure Storage..." " INFO"
		$commitAppUri = " mobileApps/$appId" ;
		$commitAppBody = GetAppCommitBody $contentVersionId $WELOBType;
		MakePatchRequest $commitAppUri ($commitAppBody | ConvertTo-Json);

        Write-WELog " Removing Temporary file '$tempFile'..." " INFO" -f Gray
        Remove-Item -Path " $tempFile" -Force
        Write-Information Write-WELog " Sleeping for $sleep seconds to allow patch completion..." " INFO" -f Magenta
        Start-Sleep $sleep
        Write-Information }
	
    catch {

		Write-WELog "" " INFO" ;
		Write-Information -ForegroundColor Red " Aborting with exception: $($_.Exception.ToString())" ;
	
    }

}





Write-Information if($global:authToken){

    # Setting DateTime to Universal time to work in all timezones
    $WEDateTime = (Get-Date).ToUniversalTime()

    # If the authToken exists checking when it expires
    $WETokenExpires = ($authToken.ExpiresOn.datetime - $WEDateTime).Minutes

        if($WETokenExpires -le 0){

        Write-Information " Authentication Token expired" $WETokenExpires " minutes ago" -ForegroundColor Yellow
        Write-Information # Defining Azure AD tenant name, this is the name of your Azure Active Directory (do not use the verified domain name)

            if($null -eq $WEUser -or $WEUser -eq "" ){

            $WEUser = Read-Host -Prompt " Please specify your user principal name for Azure Authentication"
            Write-Information }

        $script:authToken = Get-AuthToken -User $WEUser

        }
}



else {

    if($null -eq $WEUser -or $WEUser -eq "" ){

    $WEUser = Read-Host -Prompt " Please specify your user principal name for Azure Authentication"
    Write-Information }


$script:authToken = Get-AuthToken -User $WEUser

}






$WEAndroidSDKLocation = " C:\AndroidSDK\build-tools"
; 
$baseUrl = " https://graph.microsoft.com/beta/deviceAppManagement/"
; 
$logRequestUris = $true;
$logHeaders = $false;
$logContent = $true;

$sleep = 30













# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================