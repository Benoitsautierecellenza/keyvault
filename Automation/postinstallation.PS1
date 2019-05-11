# Send mail to vm owner with secrets URL is allowed
#
# A intégrer en Runbook
# Reste l'envoi de mail
# Améliorer la gestion d'erreur
#
#
Param(
    [String]$ManagedApplicationResourceGroupname = "TESTDEPLOY-yozk6ftyamos4g7u5lt354gegk",
    [String]$VMName = "Testbuild",
    [String]$SubscriptionID = "e4441a21-7e27-4163-a2e4-521954795fd4"
)
#
# Constants begin
#
$BastionServiceTag =  @{Service= "Bastion"}
$BastionSelfRebootPolicyTagName = "SelfRebootPolicy"
$BastionSelfStopPolicyTagName = "SelfStopPolicy"
$BastionSelfStartPolicyTagName = "SelfStartPolicy"
[String]$StartWebHookUriSecretName = "StartWebHookUri" 
[String]$StopWebHookUriSecretName =  "StopWebHookUri"
[String]$RebootWebHookUriSecretName = "RebootWebHookUri"
[String]$AutomationAccountInstanceName = "ManagedApplication"
[string]$AutomationAccountInstanceRGName = "ManagedApplication"
[String]$AutomationManagedApplicationStartVmRunbookName = "ManagedApplicationStartMyVM"
[String]$AutomationManagedApplicationStopVmRunbookName = "ManagedApplicationStopMyVM"
[String]$AutomationManagedApplicationRebootVmRunbookName = "ManagedApplicationRebootMyVM"
[Int]$WebHookExpirationPeriod = 7
#
# Constants End
#
try {
  #
  # Connecting to Azure Subscription provided as parameter
  #
  Set-AzContext -Subscription $SubscriptionID  
  $SubscriptionName = (get-azcontext).Subscription.Name
  Write-output "Connected to Azure Subscription $SubscriptionName."
}
catch {
  Write-Output "Unable to connect to Subscription $SubscriptionID."
  exit
}
#
# Searching for Resource group containing resources
# OK
try {
  Write-output "Searching for Resource group named $ManagedApplicationResourceGroupname in subscription $SubscriptionName ."
  $CheckForRG = Get-AzResourceGroup -Name $ManagedApplicationResourceGroupname -ErrorAction SilentlyContinue
  If($CheckForRG.Count -eq 1)
  {
    Write-output "Resource group named $ManagedApplicationResourceGroupname found in subscription $SubscriptionName ."
  }
  else {
    Write-output "Resource group named $ManagedApplicationResourceGroupname not found in subscription $SubscriptionName ."
    Exit
  }
}
catch {
  Write-output "Resource group named $ManagedApplicationResourceGroupname not found in subscription $SubscriptionName ."
  exit
}
#
# Searching for virtual machine in resource group
# OK
try {
  Write-Output "Searching for virtual machine named $VMName in Resource Group $ManagedApplicationResourceGroupname."
  $CheckforVM = get-azvm -ResourceGroupName $ManagedApplicationResourceGroupname -Name $VMName -ErrorAction SilentlyContinue
  If ($CheckforVM.Count -eq 1)
  {
    Write-Output "Virtual machine named $VMName found in Resource Group $ManagedApplicationResourceGroupname."
  }
  else {
    Write-Output "Unable to locate Virtual machine named $VMName in Resource Group $ManagedApplicationResourceGroupname."
    exit  
  }
}
catch {
  Write-Output "Unable to locate Virtual machine named $VMName in Resource Group $ManagedApplicationResourceGroupname."
  exit
}
#
# Check for Service Tag in Virtual Machine Object
# OK
If ($CheckforVM.Tags.keys -contains $($BastionServiceTag.keys))
{
  #
  # Service tag for Bastion exists, so we must be able to find related tags for Bastion policies
  # OK
  Write-Output "Virtual Machine Tag $($BastionServiceTag.keys) is present on Virtual machine $Vmname. This virtual machine is realted to the Bastion Service."
  $SelfStartPolicy = $CheckforVM.Tags[$BastionSelfStartPolicyTagName]
  $SelfStopPolicy = $CheckforVM.Tags[$BastionSelfStopPolicyTagName]
  $SelfRebootPolicy = $CheckforVM.Tags[$BastionSelfRebootPolicyTagName]
  $Message = "Your bastion virtual machine just provisioned.`r`n"
  $RunbookParameters = @{"ResourceGroupname"=$ManagedApplicationResourceGroupname;"VMName"=$VMName}
  $hookParams = @{
      'AutomationAccountName' = $AutomationAccountInstanceName;
      'ResourceGroupName'     = $AutomationAccountInstanceRGName;
      'IsEnabled'             = $true;
      'ExpiryTime'            = (get-date).AddDays($WebHookExpirationPeriod);
      'Parameters'            = $RunbookParameters
    }
}
else {
  Write-Output "Virtual Machine Tag $($BastionServiceTag.keys) is not present on Virtual machine $Vmname. This virtual machine is not realted to the Bastion Service."
}
#
# Search for KeyVault instance in resource group
# OK
$CheckForKeyVault = Get-AzKeyVault -ResourceGroupName $ManagedApplicationResourceGroupname -ErrorAction SilentlyContinue
If ($CheckForKeyVault.Count -eq 1)
{
  Write-Output "One Key Vault instance found in Resource Group $ManagedApplicationResourceGroupname : $($CheckForKeyVault.VaultName)"                
}
else {
  Write-Output "No Key Vault instance found in  Resource Group $ManagedApplicationResourceGroupname."                
  Exit
}
if ($SelfStartPolicy -like "Yes")
{
  Write-Output "Self-Start Policy parameter enabled."
  Write-Output "Generating a dedicated Webhook for $StartWebHookUriSecretName for Runbook $AutomationManagedApplicationStartVmRunbookName."
  $webhookOutput = New-AzAutomationWebhook @hookParams -Name $((New-Guid).guid) -RunbookName $AutomationManagedApplicationStartVmRunbookName -Force
  $SecretValue = ConvertTo-SecureString -String $webhookOutput.WebhookURI -AsPlainText -Force
  Set-AzKeyVaultSecret -VaultName $($checkForKeyVault.VaultName) -Name $StartWebHookUriSecretName -SecretValue $SecretValue -NotBefore ((get-date).ToUniversalTime()) -Expires (get-date).AddDays($WebHookExpirationPeriod) -ContentType 'text/Plain' -Tag $BastionServiceTag | Out-Null
  Write-Output "New Webhook for $StartWebHookUriSecretName Stored as secret in $($checkForKeyVault.VaultName)"
  $Message += "Secret URL to perform a Self-Start for your bastion is : $($webhookOutput.WebhookURI) `r`n"
}
else {
  Write-Output "Self-Start Policy parameter disabled."
}
if ($SelfStopPolicy -like "Yes")
{
  Write-Output "Self-Stop Policy parameter enabled."
  Write-Output "Generating a dedicated Webhook for $StopWebHookUriSecretName for Runbook $AutomationManagedApplicationStopVmRunbookName."
  $webhookOutput = New-AzAutomationWebhook @hookParams -Name $((New-Guid).guid) -RunbookName $AutomationManagedApplicationStopVmRunbookName -Force
  $SecretValue = ConvertTo-SecureString -String $webhookOutput.WebhookURI -AsPlainText -Force
  Set-AzKeyVaultSecret -VaultName $($checkForKeyVault.VaultName) -Name $StopWebHookUriSecretName -SecretValue $SecretValue -NotBefore ((get-date).ToUniversalTime()) -Expires (get-date).AddDays($WebHookExpirationPeriod) -ContentType 'text/Plain' -Tag $BastionServiceTag | Out-Null
  Write-Output "New Webhook for $StopWebHookUriSecretName Stored as secret in $($checkForKeyVault.VaultName)"
  $Message += "Secret URL to perform a Self-Stop  for your bastion is : $($webhookOutput.WebhookURI) `r`n"
}
else {
  Write-Output "Self-Stop Policy parameter enabled."
}
if ($SelfRebootPolicy -like "Yes")
{
  Write-Output "Self-Reboot Policy parameter enabled."

  Write-Output "Generating a dedicated Webhook for $RebootWebHookUriSecretName for Runbook $AutomationManagedApplicationRebootVmRunbookName."
  $webhookOutput = New-AzAutomationWebhook @hookParams -Name $((New-Guid).guid) -RunbookName $AutomationManagedApplicationRebootVmRunbookName -Force
  $SecretValue = ConvertTo-SecureString -String $webhookOutput.WebhookURI -AsPlainText -Force
  Set-AzKeyVaultSecret -VaultName $($checkForKeyVault.VaultName) -Name $RebootWebHookUriSecretName -SecretValue $SecretValue -NotBefore ((get-date).ToUniversalTime()) -Expires (get-date).AddDays($WebHookExpirationPeriod) -ContentType 'text/Plain' -Tag $BastionServiceTag | Out-Null
  Write-Output "New Webhook for $RebootWebHookUriSecretName Stored as secret in $($checkForKeyVault.VaultName)"
  $Message += "Secret URL to perform a Self-Stop  for your bastion is : $($webhookOutput.WebhookURI) `r`n"
}
else {
  Write-Output "Self-Reboot Policy parameter enabled."
}
exit
# Gérer les trois Policy
                  #
                  # Generating Email for user
                  #
# $ManagedApplicationNameInstance.Properties.parameters.vmOwner.value

