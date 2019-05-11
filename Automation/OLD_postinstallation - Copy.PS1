# Send mail to vm owner with secrets URL is allowed
#
# Input : Managed Application Name
#
# Revoir car le Input, c'est la souscription, le resource group et la VM
#
#
Param(
    [String]$ManagedApplicationName = "BastionBuild68cdbeb03c4545a391d41a9ffff931e1"
)
$ServiceTag = @{ServiceType= "Bastion"}
[String]$StartWebHookUriSecretName = "StartWebHookUri" 
[String]$StopWebHookUriSecretName =  "StopWebHookUri"
[String]$RebootWebHookUriSecretName = "RebootWebHookUri"
[String]$AutomationAccountInstanceName = "ManagedApplication"
[string]$AutomationAccountInstanceRGName = "ManagedApplication"
[String]$AutomationManagedApplicationStartVmRunbookName = "ManagedApplicationStartMyVM"
[String]$AutomationManagedApplicationStopVmRunbookName = "ManagedApplicationStopMyVM"
[String]$AutomationManagedApplicationRebootVmRunbookName = "ManagedApplicationRebootMyVM"
[Int]$WebHookExpirationPeriod = 7
$SubscriptionID = "e4441a21-7e27-4163-a2e4-521954795fd4"
Set-AzContext -Subscription $SubscriptionID
$SubscriptionName = (get-azcontext).Subscription.Name
$ManagedApplisationsInstances = Get-AzManagedApplication
If ($ManagedApplisationsInstances.count -GT 0)
{
    #
    # One or more Managed applications deployed in current subscription
    # OK
    [Bool]$ManagedApplication_FoundFlag = $False
    Write-output "$($ManagedApplisationsInstances.count) Managed Application instances deployed in $SubscriptionName"
    Foreach ($ManagedApplicationNameInstance in $ManagedApplisationsInstances)
    {
        #
        # Process Managed Application
        # OK
        If ($ManagedApplicationNameInstance.Name -Match $ManagedApplicationName)
        {
            #
            # Managed application found
            # OK
            $ManagedApplication_FoundFlag = $True
            Write-Output "Managed Application $ManagedApplicationName found in subscription $Subscriptionname."
            $chaine = $ManagedApplicationNameInstance.Properties.managedResourceGroupId
            $pos = $Chaine.lastindexof("/")
            $ManagedApplicationRG = $Chaine.substring($pos+1, (($Chaine.Length) - ($Pos+1)))
            #
            # Find Key Vault in $ManagedApplicationRG
            # 
            $CheckForKeyVault = Get-AzKeyVault -ResourceGroupName $ManagedApplicationRG -ErrorAction SilentlyContinue
            If ($CheckForKeyVault.Count -eq 1)
            {
                #
                # Key Vault instance found for Managed Application
                #
                Write-Output "Found Key Vault instance named $($checkForKeyVault.VaultName) in Resource Group $ManagedApplicationRG"
                #
                # Generating new Runbook parameters
                # OK
                $Message = "Your bastion virtual machine just provisioned.`r`n"
                $RunbookParameters = @{"ResourceGroupname"=$ManagedApplicationNameInstance.ResourceGroupName;"ManagedApplicationName"=$ManagedApplicationNameInstance.Name}
                $hookParams = @{
                    'AutomationAccountName' = $AutomationAccountInstanceName;
                    'ResourceGroupName'     = $AutomationAccountInstanceRGName;
                    'IsEnabled'             = $true;
                    'ExpiryTime'            = (get-date).AddDays($WebHookExpirationPeriod);
                    'Parameters'            = $RunbookParameters
                  }
                  Write-Output "Self Start Policy parameter value is : $($ManagedApplicationNameInstance.Properties.parameters.selfStartPolicy.value)."
                  If ($ManagedApplicationNameInstance.Properties.parameters.selfStartPolicy.value -eq "Yes")
                  {
                    #
                    # Only generate a Self Start Webhook URI if policy is enabled
                    # OK
                    Write-Output "Generating a dedicated Webhook for $StartWebHookUriSecretName for Runbook $AutomationManagedApplicationStartVmRunbookName."
                    $webhookOutput = New-AzAutomationWebhook @hookParams -Name $((New-Guid).guid) -RunbookName $AutomationManagedApplicationStartVmRunbookName -Force
                    $SecretValue = ConvertTo-SecureString -String $webhookOutput.WebhookURI -AsPlainText -Force
                    Set-AzKeyVaultSecret -VaultName $($checkForKeyVault.VaultName) -Name $StartWebHookUriSecretName -SecretValue $SecretValue -NotBefore ((get-date).ToUniversalTime()) -Expires (get-date).AddDays($WebHookExpirationPeriod) -ContentType 'text/Plain' -Tag $ServiceTag | Out-Null
                    Write-Output "New Webhook for $StartWebHookUriSecretName Stored as secret in $($checkForKeyVault.VaultName)"
                    $Message += "Secret URL to perform a Self-Start for your bastion is : $($webhookOutput.WebhookURI) `r`n"
                  }
                  else {
                      Write-Output "No dedicated webhook generated for self-start because policy is disabled."
                      $Message += "No dedicated webhook generated for self-start because policy is disabled. `r`n"
                  }

                  Write-Output "Self Start Policy parameter value is : $($ManagedApplicationNameInstance.Properties.parameters.selfStopPolicy.value)."
                  If ($ManagedApplicationNameInstance.Properties.parameters.selfStopPolicy.value -eq "Yes")
                  {
                    #
                    # Only generate a Self Stop Webhook URI if policy is enabled
                    # OK
                    Write-Output "Generating a dedicated Webhook for $StopWebHookUriSecretName for Runbook $AutomationManagedApplicationStopVmRunbookName."
                    $webhookOutput = New-AzAutomationWebhook @hookParams -Name $((New-Guid).guid) -RunbookName $AutomationManagedApplicationStopVmRunbookName -Force
                    $SecretValue = ConvertTo-SecureString -String $webhookOutput.WebhookURI -AsPlainText -Force
                    Set-AzKeyVaultSecret -VaultName $($checkForKeyVault.VaultName) -Name $StopWebHookUriSecretName -SecretValue $SecretValue -NotBefore ((get-date).ToUniversalTime()) -Expires (get-date).AddDays($WebHookExpirationPeriod) -ContentType 'text/Plain' -Tag $ServiceTag | Out-Null
                    Write-Output "New Webhook for $StopWebHookUriSecretName Stored as secret in $($checkForKeyVault.VaultName)"
                    $Message += "Secret URL to perform a Self-Stop for your bastion is : $($webhookOutput.WebhookURI) `r`n"
                  }
                  else {
                    Write-Output "No dedicated webhook generated for self-stop because policy is disabled."
                    $Message += "No dedicated webhook generated for self-stop because policy is disabled. `r`n"
                  }
                  Write-Output "Self Start Policy parameter value is : $($ManagedApplicationNameInstance.Properties.parameters.selfRebootPolicy.value)."
                  If ($ManagedApplicationNameInstance.Properties.parameters.selfStopPolicy.value -eq "Yes")
                  {
                    #
                    # Only generate a Self Reboot Webhook URI if policy is enabled
                    # OK
                    Write-Output "Generating a dedicated Webhook for $RebootWebHookUriSecretName for Runbook $AutomationManagedApplicationRebootVmRunbookName."
                    $webhookOutput = New-AzAutomationWebhook @hookParams -Name $((New-Guid).guid) -RunbookName $AutomationManagedApplicationRebootVmRunbookName -Force
                    $SecretValue = ConvertTo-SecureString -String $webhookOutput.WebhookURI -AsPlainText -Force
                    Set-AzKeyVaultSecret -VaultName $($checkForKeyVault.VaultName) -Name $RebootWebHookUriSecretName -SecretValue $SecretValue -NotBefore ((get-date).ToUniversalTime()) -Expires (get-date).AddDays($WebHookExpirationPeriod) -ContentType 'text/Plain' -Tag $ServiceTag | Out-Null
                    Write-Output "New Webhook for $RebootWebHookUriSecretName Stored as secret in $($checkForKeyVault.VaultName)"
                    $Message += "Secret URL to perform a Self-Stop for your bastion is : $($webhookOutput.WebhookURI) `r`n"
                  }
                  else {
                    Write-Output "No dedicated webhook generated for self-reboot because policy is disabled."
                    $Message += "No dedicated webhook generated for self-reboot because policy is disabled.`r`n"
                  }
                  $Message
                  #
                  # Generating Email for user
                  #
# $ManagedApplicationNameInstance.Properties.parameters.vmOwner.value
                  



                


            }
            else {
                #
                # No KeyVault found
                # OK
                Write-Output "No Key Vault instance related to Managed Application $($ManagedApplicationInstance.Name) in Resource Group $ManagedApplicationRG."                
            }

            #
            # 
            #
        }
    }
    If ($ManagedApplication_FoundFlag -eq $False)
    {
        #
        # Managed Application not found
        # OK
        Write-Output "Managed Application $ManagedApplicationName not found in subscription $Subscriptionname."
    }

}
else {
    Write-Output "No Managed Application instance deployed in subscription $SubscriptionName."
}