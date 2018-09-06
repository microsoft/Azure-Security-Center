#region List all ASC PowerShell commands
Get-Command -Module AzureRm.Security
#endregion

#region Azure Microsoft.Security ResourceProvider registration
#Verify registration
Get-AzureRmResourceProvider -ProviderNamespace Microsoft.Security | Select-Object ProviderNamespace, Locations, RegistrationState

#Register the Microsoft.Security resource provider
Register-AzureRmResourceProvider -ProviderNamespace Microsoft.Security
#endregion

#region Assign ASC Azure Policy
#Assign the ASC Azure Policies to a subscription
$mySub = Get-AzureRmSubscription -SubscriptionName "<mySubscriptionName>"
$subscription = "/subscriptions/$mySub"
$policySetDefinition = Get-AzureRmPolicySetDefinition | Where-Object {$_.Properties.DisplayName -eq "[Preview]: Enable Monitoring in Azure Security Center"}
New-AzureRmPolicyAssignment -PolicySetDefinition $policySetDefinition -Name "<YourAssignmentName>" -Scope $subscription -PolicyParameter "{}"

#Assign the ASC Azure Policies to a resource group
$resourceGroup = Get-AzureRmResourceGroup -Name "<myResourceGroupName>"
$policySetDefinition = Get-AzureRmPolicySetDefinition | Where-Object {$_.Properties.DisplayName -eq "[Preview]: Enable Monitoring in Azure Security Center"}
New-AzureRmPolicyAssignment -PolicySetDefinition $policySetDefinition -Name "<YourAssignmentName>" -Scope $resourceGroup.ResourceId -PolicyParameter "{}"
#endregion

#region GET Autoprovision settings for subscriptions
#Get Autoprovision setting for the current scope
Get-AzureRmSecurityAutoProvisioningSetting

#Get the Autoprovision setting for all Azure subscriptions 
Get-AzureRmContext -ListAvailable -PipelineVariable myAzureSubs | Set-AzureRmContext | ForEach-Object{
    Write-Output $myAzureSubs
    Get-AzureRmSecurityAutoProvisioningSetting | Select-Object AutoProvision
    "-"*100
}

#Get the AutoProvision settings based on an input file
#Get subscriptions from Azure
$subscriptions = Get-AzureRmSubscription

#Create an output file with all the subscriptions names
$subscriptions.Name | Out-File "C:\Temp\Subscriptions.txt"

$subscriptionFile = Get-Content -Path "C:\Temp\Subscriptions.txt"
foreach($subNameFromFile in $subscriptionFile){
    Select-AzureRmSubscription $subNameFromFile | Out-Null
    $autoSettings = Get-AzureRmSecurityAutoProvisioningSetting
    Write-Output ("SubscriptionName: " + $subNameFromFile + " - AutoProvisionSetting: " + $autoSettings.AutoProvision)
}
#endregion

#region SET AutoProvision settings
#Set AutoProvision to ON for the current scope
Set-AzureRmSecurityAutoProvisioningSetting -Name "default" -EnableAutoProvision

#Set AutoProvision to OFF for the current scope
Set-AzureRmSecurityAutoProvisioningSetting -Name "default"

#Set AutoProvision to ON for all subscriptions
Get-AzureRmContext -ListAvailable -PipelineVariable myAzureSubs | Set-AzureRmContext | ForEach-Object{
    Set-AzureRmSecurityAutoProvisioningSetting -Name "default" -EnableAutoProvision
}

#SET Autoprovision setting to ON, using an input file
$subscriptionFile = Get-Content -Path "C:\temp\Subscriptions.txt"
foreach($subNameFromFile in $subscriptionFile){
    Select-AzureRmSubscription $subNameFromFile | Out-Null
    Write-Output "Enabling Autoprovision for subscription $subNameFromFile"
    Set-AzureRmSecurityAutoProvisioningSetting -Name "default" -EnableAutoProvision
}

#SET Autoprovision setting to OFF, using an input file
$subscriptionFile = Get-Content -Path "C:\temp\Subscriptions.txt"
foreach($subNameFromFile in $subscriptionFile){
    Select-AzureRmSubscription $subNameFromFile | Out-Null
    Write-Output "Disabling Autoprovision for subscription $subNameFromFile"
    Set-AzureRmSecurityAutoProvisioningSetting -Name "default"
}
#endregion

#region Azure Security Pricing
#Get current pricing tier
Get-AzureRmSecurityPricing | Select-Object Name, PricingTier

#Set Azure Security Center pricing tier for the default scope, use either "Standard" or "Free"
Set-AzureRmSecurityPricing -Name default -PricingTier "Standard"

#region Security Alerts
#Tip: you can filter out fields of interest by using Select-Object
Get-AzureRmSecurityAlert
Get-AzureRmSecurityAlert | Select-Object AlertDisplayName, CompromisedEntity, Description
#endregion

#region Security Contact information
#Get the security contact in the current scope
Get-AzureRmSecurityContact

#Get all the security contacts
Get-AzureRmContext -ListAvailable -PipelineVariable myAzureSubs | Set-AzureRmContext | ForEach-Object{
    Get-AzureRmSecurityContact}

#Set a security contact for the current scope. For the parameter "-Name", you need to use "default1", "default2", etc.
Set-AzureRmSecurityContact  -Name "default1" -Email "john@johndoe.com" -Phone "12345" -AlertAdmin -NotifyOnAlert

#SET security contacts for all subscriptions (assuming you have the appropriete permissions)
Get-AzureRmContext -ListAvailable -PipelineVariable myAzureSubs | Set-AzureRmContext | ForEach-Object{
    Set-AzureRmSecurityContact -Email "john@doe.com" `
    -NotifyOnAlert -phone "12345" `
    -Name 'default1' -AlertAdmin }
#endregion

#region Security Compliance
$compliance = Get-AzureRmSecurityCompliance   

#example, get the compliance percentage for your subscription
$compliance[0].AssessmentResult
#endregion

#region workspace settings
#Get the configured workspace for the current scope
$workspace = Get-AzureRmSecurityWorkspaceSetting

#display the configured workspaceID and workspaceName
$workspace.WorkspaceId

#Set the workspace
#get the workspaceName and workspaceID - this requires the module AzureRm.OperationalInsights
$workspaceObj = Get-AzureRmOperationalInsightsWorkspace -Name "<workspaceName>" -ResourceGroupName "<workspaceResourceGroupName"
Set-AzureRmSecurityWorkspaceSetting -Name default -WorkspaceId $workspaceObj.ResourceId
#endregion