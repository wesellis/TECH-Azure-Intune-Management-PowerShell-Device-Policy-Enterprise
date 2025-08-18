<#
.SYNOPSIS
    Invoke Biosinventorytola

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
    We Enhanced Invoke Biosinventorytola

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
  Collect OEM BIOS verson information from HP, Dell and Lenovo based on querying Log Analytics for excisting models in your environment. 

.DESCRIPTION
  Collect OEM BIOS verson information from HP, Dell and Lenovo based on querying Log Analytics for excisting models in your environment. 
  This script is to run in Azure Automation - verfied on Powershell 5.1 and Powershell 7.1 

.NOTES
    Purpose/Change: Initial script development
    Author:      Jan Ketil Skanke & Maurice Daly
    Contact:     @JankeSkanke @Modaly_IT
    Created:     2020-10-11
    Updated:     2021-09-08
    Version history:
    1.0.0 - (2021-Nov-3) Initial version
.EXAMPLE

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$WEWorkspaceID = Get-AutomationVariable -Name 'WorkspaceID'
$WESharedKey = Get-AutomationVariable -Name 'WSSharedKey'

$WESubscriptionID = Get-AutomationVariable -Name 'DeviceInventoryLogSubscriptionID'

$WEBIOSLogType = " OEMBIOSInformation"

$WEInventoryLog = " DeviceInventory_CL"

$WETimeStampField = "" 



Function New-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource) {
    $xHeaders = " x-ms-date:" + $date
    $stringToHash = $method + " `n" + $contentLength + " `n" + $contentType + " `n" + $xHeaders + " `n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId, $encodedHash
    return $authorization
}#endfunction
Function Send-LogAnalyticsData($customerId, $sharedKey, $body, $logType) {
    $method = " POST"
    $contentType = " application/json"
    $resource = " /api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString(" r" )
    $contentLength = $body.Length
    $signature = New-Signature `
        -customerId $customerId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource
    
    $uri = " https://" + $customerId + " .ods.opinsights.azure.com" + $resource + " ?api-version=2016-04-01"
    
    #validate that payload data does not exceed limits
    if ($body.Length -gt (31.9 *1024*1024))
    {
        throw(" Upload payload is too big and exceed the 32Mb limit for a single upload. Please reduce the payload size. Current payload size is: " + ($body.Length/1024/1024).ToString(" #.#" ) + " Mb" )
    }

   ;  $payloadsize = (" Upload payload size is " + ($body.Length/1024).ToString(" #.#" ) + " Kb " )
    
   ;  $headers = @{
        " Authorization"        = $signature;
        " Log-Type"             = $logType;
        " x-ms-date"            = $rfc1123date;
        " time-generated-field" = $WETimeStampField;
    }
    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing 
    $statusmessage = " $($response.StatusCode) : $($payloadsize)"
    return $statusmessage 
}#endfunction
function WE-Get-XMLData ($WEXMLUrl) {
    $xml = New-Object xml
    $resolver = New-Object -TypeName System.Xml.XmlUrlResolver
    $resolver.Credentials = [System.Net.CredentialCache]::DefaultCredentials
    $reader = New-Object -TypeName System.Xml.XmlReaderSettings
    $reader.XmlResolver = $resolver
    $reader = [System.Xml.XmlReader]::Create($WEXMLUrl, $reader) 
    $xml.Load($reader)
    [xml]$response = $xml
    return $response
}#endfunction



$WEConnecting = Connect-AzAccount -Identity -Subscription $WESubscriptionID


$WEDellSystemSKUsQuery = " $($WEInventoryLog) | where Manufacturer_s contains `" Dell`" | distinct SystemSKU_s"
$WEDellSystemSKUs = Invoke-AZOperationalInsightsQuery -WorkspaceId $WEWorkspaceID -Query $WEDellSystemSKUsQuery

Invoke-WebRequest -Uri " https://downloads.dell.com/catalog/CatalogPC.cab" -OutFile (Join-Path -Path $env:TEMP -ChildPath " CatalogPC.cab" )
Expand-7Zip -ArchiveFileName (Join-Path -Path $env:TEMP -ChildPath " CatalogPC.cab" ) -TargetPath $env:TEMP
[xml]$WEDellBIOSXML = Get-Content -Path (Join-Path -Path $env:TEMP -ChildPath " CatalogPC.xml" )
foreach($WESKU in $WEDellSystemSKUs.Results.SystemSKU_s){
    if (-not([string]::IsNullOrEmpty($WESku))){
        #$WEDellBiosXML = Get-XMLData -XMLUrl " https://azurefilesnorway.blob.core.windows.net/dat/CatalogPC.xml"
        $WEDellBIOSLatest = $WEDellBiosXML.Manifest.SoftwareComponent
        $WEDellBIOSLatest = $WEDellBiosXML.Manifest.SoftwareComponent | Where-Object {($_.name.display." #cdata-section" -match " BIOS" ) -and ($_.SupportedSystems.Brand.Model.SystemID -match $WESKU)}
        $WECurrentDellBIOSVersion = $WEDellBIOSLatest.dellVersion
        [DateTime]$WECurrentDellBIOSDate = $WEDellBIOSLatest.releaseDate
        #Write-Output " SKU:$($sku),Version:$($WEBiosLatest.ver),Date:$($WEBiosLatest.date)"
        $WEBIOSInventory = New-Object System.Object
        $WEBIOSInventory | Add-Member -MemberType NoteProperty -Name " SKU" -Value " $WESKU" -Force   
        $WEBIOSInventory | Add-Member -MemberType NoteProperty -Name " OEMVersion" -Value " $WECurrentDellBIOSVersion" -Force   
        $WEBIOSInventory | Add-Member -MemberType NoteProperty -Name " OEMDate" -Value " $WECurrentDellBIOSDate" -Force      
        $WEBIOSInventory | Add-Member -MemberType NoteProperty -Name " OEM" -Value " Dell" -Force  
        $WEBIOSJson = $WEBIOSInventory | ConvertTo-Json
        #write-output $WEBIOSJson
        try {
            $WEResponseBIOSInventory = Send-LogAnalyticsData -customerId $WEWorkspaceID -sharedKey $WESharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($WEBIOSJson)) -logType $WEBIOSLogType -ErrorAction Stop
            Write-Output " BIOS Information injected for SKU $($WESKU)"
        } catch {
            $WEResponseBIOSInventory = " Error Code: $($_.Exception.Response.StatusCode.value__)"
            $WEResponseBIOSMessage = $_.Exception.Message
            Write-Output " Error $($WEResponseBIOSInventory), Message $($WEResponseBIOSMessage)"
        }
    }      
}



$WEHPSystemSKUsQuery = " $($WEInventoryLog) | where Manufacturer_s contains `" HP`" or Manufacturer_s contains `" Hewlett`" | distinct SystemSKU_s"
$WEHPSystemSKUs = Invoke-AZOperationalInsightsQuery -WorkspaceId $WEWorkspaceID -Query $WEHPSystemSKUsQuery

foreach($WESKU in $WEHPSystemSKUs.Results.SystemSKU_s){
    if (-not([string]::IsNullOrEmpty($WESku))){
        $WEBIOSXML = Get-XMLData -XMLUrl " https://ftp.ext.hp.com/pub/pcbios/$($WESKU)/$($WESKU).xml" 
        $WEBIOSLatest = $WEBIOSXML.BIOS.Rel | Sort-Object -Descending -Property ver | Select-Object -First 1
        $WECurrentBIOSVersion = $WEBIOSLatest.ver
        [DateTime]$WECurrentBIOSDate = $WEBIOSLatest.date
        
        #Write-Output " SKU:$($sku),Version:$($WEBiosLatest.ver),Date:$($WEBiosLatest.date)"
        $WEBIOSInventory = New-Object System.Object
        $WEBIOSInventory | Add-Member -MemberType NoteProperty -Name " SKU" -Value " $WESKU" -Force   
        $WEBIOSInventory | Add-Member -MemberType NoteProperty -Name " OEMVersion" -Value " $WECurrentBIOSVersion" -Force   
        $WEBIOSInventory | Add-Member -MemberType NoteProperty -Name " OEMDate" -Value " $WECurrentBIOSDate" -Force 
        $WEBIOSInventory | Add-Member -MemberType NoteProperty -Name " OEM" -Value " HP" -Force             
        $WEBIOSJson = $WEBIOSInventory | ConvertTo-Json
        #write-output $WEBIOSJson
        try {
            $WEResponseBIOSInventory = Send-LogAnalyticsData -customerId $WEWorkspaceID -sharedKey $WESharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($WEBIOSJson)) -logType $WEBIOSLogType -ErrorAction Stop
            Write-Output " BIOS Information injected for SKU $($WESKU)"
        } catch {
            $WEResponseBIOSInventory = " Error Code: $($_.Exception.Response.StatusCode.value__)"
            $WEResponseBIOSMessage = $_.Exception.Message
            Write-Output " Error $($WEResponseBIOSInventory), Message $($WEResponseBIOSMessage)"
        }        
    }
}



$WELenovoSystemSKUsQuery = " $($WEInventoryLog) | where Manufacturer_s contains `" Lenovo`" | distinct SystemSKU_s"
$WELenovoSystemSKUs = Invoke-AZOperationalInsightsQuery -WorkspaceId $WEWorkspaceID -Query $WELenovoSystemSKUsQuery

$WELenovoBiosBase = " https://download.lenovo.com/catalog/"
foreach($WESKU in $WELenovoSystemSKUs.Results.SystemSKU_s){
    if (-not([string]::IsNullOrEmpty($WESku))){
        Write-Output " Trying Lenovo $WESKU"
        try{
            $WERequest = Invoke-WebRequest -uri ($WELenovoBiosBase + " $WESKU" + " _Win10.xml" )
            $WEURLStatus = $WERequest.StatusCode
         } catch{
            $WEURLStatus = $($_.Exception.Response.StatusCode.Value__)
         }
        Write-Output $WEURLStatus 
        if ($WEURLStatus -ne " 404" ){
        [xml]$WEValidBIOSLocationXML = Get-XMLData -XMLUrl ($WELenovoBiosBase + " $WESKU" + " _Win10.xml" )
        $WELenovoModelBIOSInfo = $WEValidBIOSLocationXML.Packages.Package | Where-Object {$_.Category -match " BIOS" } | Sort-Object Location -Descending | Select-Object -First 1
            $WELenovoBIOSLocationInfo = $WELenovoModelBIOSInfo.location
            $WELatestOEMBIOSInfo = (Get-XMLData -XMLUrl $WELenovoBIOSLocationInfo).Package

            $WECurrentBIOSVersion = $WELatestOEMBIOSInfo.version
            [DateTime]$WECurrentBIOSDate = $WELatestOEMBIOSInfo.ReleaseDate
            
            #Write-Output " SKU:$($sku),Version:$($WEBiosLatest.ver),Date:$($WEBiosLatest.date)"
                $WEBIOSInventory = New-Object System.Object
                $WEBIOSInventory | Add-Member -MemberType NoteProperty -Name " SKU" -Value " $WESKU" -Force   
                $WEBIOSInventory | Add-Member -MemberType NoteProperty -Name " OEMVersion" -Value " $WECurrentBIOSVersion" -Force   
                $WEBIOSInventory | Add-Member -MemberType NoteProperty -Name " OEMDate" -Value " $WECurrentBIOSDate" -Force  
                $WEBIOSInventory | Add-Member -MemberType NoteProperty -Name " OEM" -Value " Lenovo" -Force       
                $WEBIOSJson = $WEBIOSInventory | ConvertTo-Json
        }
        else {
            $WEBIOSInventory = New-Object System.Object
            $WEBIOSInventory | Add-Member -MemberType NoteProperty -Name " SKU" -Value " $WESKU" -Force   
            $WEBIOSInventory | Add-Member -MemberType NoteProperty -Name " OEMVersion" -Value " NA" -Force   
            $WEBIOSInventory | Add-Member -MemberType NoteProperty -Name " OEMDate" -Value " NA" -Force       
            $WEBIOSInventory | Add-Member -MemberType NoteProperty -Name " OEM" -Value " Lenovo" -Force       
            $WEBIOSJson = $WEBIOSInventory | ConvertTo-Json
        }
        try {
            $WEResponseBIOSInventory = Send-LogAnalyticsData -customerId $WEWorkspaceID -sharedKey $WESharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($WEBIOSJson)) -logType $WEBIOSLogType -ErrorAction Stop
            Write-Output " BIOS Information injected for SKU $($WESKU)"
        } catch {
            $WEResponseBIOSInventory = " Error Code: $($_.Exception.Response.StatusCode.value__)"
            $WEResponseBIOSMessage = $_.Exception.Message
            Write-Output " Error $($WEResponseBIOSInventory), Message $($WEResponseBIOSMessage)"
        }
       ;  $WEValidBIOSLocationXML = $null
       ;  $WEURLStatus = $null
    }
}




# Wesley Ellis Enterprise PowerShell Toolkit
# Enhanced automation solutions: wesellis.com
# ============================================================================