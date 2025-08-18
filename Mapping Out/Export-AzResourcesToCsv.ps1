# Connect to Azure account
Connect-AzAccount

# Get list of all Azure resources
$resources = Get-AzResource -ErrorAction Stop

# Export list of resources to CSV file
$resources | Export-Csv -Path "C:\Resources.csv" -NoTypeInformation
