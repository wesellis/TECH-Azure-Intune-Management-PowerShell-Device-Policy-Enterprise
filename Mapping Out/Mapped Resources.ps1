# Connect to Azure account
Connect-AzAccount

# Get list of all Azure resources
$resources = Get-AzResource

# Export list of resources to CSV file
$resources | Export-Csv -Path "C:\Resources.csv" -NoTypeInformation
