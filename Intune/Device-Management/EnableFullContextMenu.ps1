$registryPath = "HKCU:\SOFTWARE\CLASSES\CLSID\"
$keyName = "{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}"

if (-not (Test-Path "$registryPath$keyName")) {
    New-Item -Path "$registryPath$keyName" -Force
    New-Item -Path "$registryPath$keyName\InprocServer32" -Force

    Set-ItemProperty -Path "$registryPath$keyName\InprocServer32" -Name "(Default)" -Value ""
    
    Write-Host "Registry key created successfully. Please restart your computer to apply changes."
} else {
    Write-Host "Registry key already exists."
}