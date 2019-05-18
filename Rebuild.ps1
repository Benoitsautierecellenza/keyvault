# Risque : 2 VM avec le même nom dans 2 RG différents, donc risque d'écraser les SNapshot d'un autre
# A la fin, il faut un process de purge du contenu de BastionDataSnapshot
#
# Rebuild Bastion
#
$SubscriptionID = "e4441a21-7e27-4163-a2e4-521954795fd4"
$ServiceTag = @{ServiceType= "Bastion"}
$BastionLifeDurationInDays = 7
Set-AzContext -Subscription $SubscriptionID
$SubscriptionName = (get-azcontext).Subscription.Name
[String]$BastionDataSnapshotRGName = "BastionDataSnapshots"
[String]$ManagedApplicationRGName = "ManagedApplication"
[String]$RebuildTag = "Rebuild"
[String]$LocalAdministratorPasswordSecretName = "AdministratorPassword"
[String]$LocalAdministratorUserNameSecretName = "LocalAdministratorUserName"
[String]$VMOwnerSecretName = "VMOwner"
#
# Parse Azure Managed applications
#
$ListManagedApplicationInstances = Get-AzManagedApplication
If ($ListManagedApplicationInstances.Count -GT 0)
{
    Write-Output "$($ListManagedApplicationInstances.Count) Managed Application(s) deployed in Subscription $SubscriptionName."
    Foreach($ManagedApplicationInstance in $ListManagedApplicationInstances)
    {
        #
        # Process all Managed application deployed in the subscription
        #
        $CheckServiceType = $ManagedApplicationInstance.Properties.parameters.serviceType.value
        If ($CheckServiceType -eq "Bastion")
        {   
            #
            # Filter Managed application with Parameters ServiceType=Bastion
            #
            Write-Output "Processing Managed application named $($ManagedApplicationInstance.name) because related to Bastion"
            [DateTime]$ManagedApplicationExpirationDate = $ManagedApplicationInstance.Properties.parameters.expiration.value
            $Chaine = $ManagedApplicationInstance.Properties.applicationDefinitionId
            $pos = $Chaine.lastindexof("/")
            $CurrentApplicationName = $Chaine.substring($pos+1, (($Chaine.Length) - ($Pos+1)))
            #
            # Vérifie si le groupe de ressources destiné à stocker les Snapshots existe ou pas
            #
        #    $CheckRG = Get-azresourcegroup -name $BastionDataSnapshotRGName -ErrorAction SilentlyContinue
        #    if ([string]::IsNullOrEmpty($CheckRG) -eq $True)
        #    {
        #        #
        #        # BastionDataSnapshots Resource Group will be created in the subscription
        #        # OK
        #        Write-Output "Resource Group named $BastionDataSnapshotRGName does yet exists in subscription $SubscriptionName."
        #        New-AzResourceGroup -Name $BastionDataSnapshotRGName -Location $ManagedApplicationInstance.Location -Tag $ServiceTag 
        #        Write-Output "Resource Group named $BastionDataSnapshotRGName successfully created in subscription $SubscriptionName."
        #    }
        #    else {
        #        #
        #        # Resource Group used to store Snapshots exists
        #        # OK
        #        Write-Output "Resource Group named $BastionDataSnapshotRGName already exists in subscription $SubscriptionName."
        #    }
     #       $ServiceTag += @{Owner= $ListManagedApplicationInstances.Properties.parameters.vmOwner.value}
            #
            # $Currentdate = Get-Date
            $Currentdate = (Get-Date).AddDays(10)       # pour simuler 10 jous dans la futur
            #
            If ($Currentdate -gt $ManagedApplicationExpirationDate)
            {
                #
                # Managed application expiration date reached
                # OK
                Write-Output "Managed Application expiration date is expired. Application will be deleted."
                If (($ManagedApplicationInstance.Properties.parameters.bastionRebuildPolicy.value) -eq "Yes")
                {
                    #
                    # Start the Rebuid process for this Managed Application
                    #
                    Write-Output "Managed Application $($ManagedApplicationInstance.name) have the Rebuild Policy flag enabled. Managed application will be rebuilded."
                    [bool]$RebuildFlag = $True
# Peut être plus nécessaire si on peut effectivement déployer une application avec le snapshot dans le RG
#                    [String]$SnapshotResourceGroupName = $BastionDataSnapshotRGName
                    [String]$SnapshotResourceGroupName = $ManagedApplicationInstance.ResourceGroupName
                }
                else {
                    #
                    # No need to perform a rebuild Process, just snapshot managed disks and delete Managed Application
                    #
                    Write-Output "Managed Application $($ManagedApplicationInstance.name) have the Rebuild Policy flag enabled. Managed application will be deleted."
                    [bool]$RebuildFlag = $False
                    [String]$SnapshotResourceGroupName = $ManagedApplicationInstance.ResourceGroupName
                }
                #
                # Get Managed Application resource Goup
                #
                $ManagedResourceGroupID = $ManagedApplicationInstance.Properties.managedResourceGroupId
                $pos = $ManagedResourceGroupID.lastindexof("/")
                $RGname = $ManagedResourceGroupID.substring($pos+1, (($ManagedResourceGroupID.Length) - ($Pos+1)))
                $CheckRG = Get-AzResourceGroup -Name $RGname -ErrorAction SilentlyContinue 
                if ([string]::IsNullOrEmpty($CheckRG) -eq $False)
                {
                    #
                    # Resource group containing application resources exists
                    # OK
                    Write-Output "Resource Group $RGname related to Managed application named $($ManagedApplicationInstance.name)."
                    $ListManagedVms = get-azvm -ResourceGroupName $RGname
                    ForEach($ManagedVM in $ListManagedVms)
                    {
                        #
                        # Process Each Virtual machine composing the Managed Application
                        # OK
                        Write-Output "Processing Virtual machine $($ManagedVM.Name)."
                        $vmstatus = (get-azvm -ResourceGroupName $RGname -Name $($ManagedVM.Name) -Status).statuses | Select-Object -last 1
                        Write-Output "Current VM Status is $($vmstatus.DisplayStatus)"
                        #
                        # Desalocate each Virtual machine composing the Managed Application
                        # OK
                        If ($($vmstatus.DisplayStatus) -notlike "VM deallocated")
                        {
                            Write-Output "Desalocatting Virtual machine $($ManagedVM.Name)."
                            Stop-AzVm -ResourceGroupName $RGname -Name $($ManagedVM.Name) -WarningAction SilentlyContinue -Force
                            $vmstatus = (get-azvm -ResourceGroupName $RGname -Name $($ManagedVM.Name) -Status).statuses | Select-Object -last 1
                            Write-Output "New VM Status is $($vmstatus.DisplayStatus)"                            
                        }
                        #
                        # Remove all existing Snaphots located in Managed Application resource groups
                        #
                        $checkforSnapshot = Get-AzSnapshot -ResourceGroupName $ManagedApplicationInstance.ResourceGroupName  -ErrorAction SilentlyContinue
                        if ([string]::IsNullOrEmpty($checkforSnapshot) -eq $False)
                        {
                            #
                            # Delete Any Managed Disk snapshots from Resource Group
                            # OK
                            Write-Output "$($checkforSnapshot.count) Managed Disks snapshot(s) exists in Resource Group $($ManagedApplicationInstance.ResourceGroupName). Will be deleted."
                            $checkforSnapshot | Remove-AzSnapshot -Force
                            Write-Output "Existing Managed disks snapshots have been deleted from $($ManagedApplicationInstance.ResourceGroupName)."
                        }
                        else {
                            #
                            # No Managed Disk Snapshot exists in Resource Group
                            # OK
                            Write-Output "No existing snapshot in resource group $($ManagedApplicationInstance.ResourceGroupName)."
                        }
                        #
                        # Parse VM Disks to create snapshots
                        #
                        $VMDataDisks =  (get-azvm -ResourceGroupName $RGname -Name $($ManagedVM.Name)).StorageProfile.DataDisks
                        ForEach ($VMDataDisk in $VMDataDisks)
                        {
                            #
                            # Process all data disks
                            #
                            Write-output "Creating new snapshots for Data Disk $($VMDataDisk.Name) from VM $($ManagedVM.Name)"
                            $Random = Get-Random -Minimum 0 -Maximum 999                            
                            $DiskSnapshotname = "SNAP" + $VMDataDisk.Name + ("{0:D3}" -f (Get-Date).DayofYear) + "_$Random"
                            $checkforSnapshot = Get-AzSnapshot -ResourceGroupName $SnapshotResourceGroupName -SnapshotName $DiskSnapshotname -ErrorAction SilentlyContinue
                            if ([string]::IsNullOrEmpty($checkforSnapshot) -eq $False)
                            {
                                #
                                # A snapshot with this name already exists, will be deleted
                                # OK
                                Write-Output "Existing Snapshot named $DiskSnapshotname already exists in Resource group $SnapshotResourceGroupName. Will be overwrited."
                                Remove-AzSnapshot -ResourceGroupName $SnapshotResourceGroupName -SnapshotName $DiskSnapshotname -Force
                            }
                            else {
                                Write-Output "Snapshot named $DiskSnapshotname does not exists in Resource group $SnapshotResourceGroupName."
                            }
                            #
                            # Create a Snapshot for the Datadisk
                            # OK
                            $DataDiskID = (Get-AzDisk -Name $VMDataDisk.name -ResourceGroupName $ManagedVM.ResourceGroupName).Id
                            $DataDiskSnapshotConfig = New-AzSnapshotConfig -SourceUri $DataDiskID `
                                -Location $ManagedVM.Location `
                                -CreateOption "Copy" `
                                -WarningAction SilentlyContinue
                            try {

                                Write-Output "Creating Azure Managed Disk snapshot named $DiskSnapshotname in resource Group $SnapshotResourceGroupName."
                                New-AzSnapshot -ResourceGroupName $SnapshotResourceGroupName -SnapshotName $DiskSnapshotname -Snapshot $DataDiskSnapshotConfig                                
                                Write-Output "Managed Disk snapshot named $DiskSnapshotname sucessfully created in resource Group $SnapshotResourceGroupName."
                            }
                            catch {
                                # gestion d'erreur à intégrer
                            }
                        }
                        Write-Output "All Data disk attached to $($ManagedVM.Name) were processed for snapshot."
                    }
                    Write-Output "All virtual machine composing the Managed Application were processed."
                }
                else {
                    Write-Output "No more resource Group $RGname related to Managed application named $($ManagedApplicationInstance.name)."
                }
                #
                # Process Delete or Rebuild
                #
                If ($RebuildFlag -eq $true)
                {
                    #
                    # Rebuild process
                    #
                    $ListManagedApplications = Get-AzManagedApplicationDefinition -ResourceGroupName $ManagedApplicationRGName
                    if ([string]::IsNullOrEmpty($ListManagedApplications) -eq $False)
                    {
                        [Bool]$Rebuild_FoundFlag = $False
                        ForEach($ParseManagedApplication in $ListManagedApplications)
                        {
                            #
                            # Parse all Managed Application available in the Resource Group
                            # OK
                            $CheckServiceType = $ParseManagedApplication.Tags.ServiceType
                            If ($CheckServiceType -eq "Bastion")
                            {
                                #
                                # Filter Managed application related to Bastion only
                                # OK
                                Write-Output "Managed application $($ParseManagedApplication.Name) is related to Bastion."
                                If (($ParseManagedApplication.tags.Keys) -contains $RebuildTag) 
                                {
                                    #
                                    # Managed Application is for rebuild purpose
                                    # OK
                                    Write-Output "Managed Application $($ParseManagedApplication.Name) is for rebuild purpose."
# Attention, mon RebuildTag est hardcodé en dur!!                                    
                                    $RebuildList = $ParseManagedApplication.Tags.Rebuild
                                    $RebuildListArray = $RebuildList.Split(",")
                                    ForEach($RebuildElement in $RebuildListArray)
                                    {
                                        #
                                        # Process each Application listed a rebuild for current Managed Application
                                        #
                                        If ($RebuildElement -Like  $CurrentApplicationName)
                                        {
                                            Write-output "Azure Managed Application $($ParseManagedApplication.Name) is the rebuild for $CurrentApplicationName."
                                            $Rebuild_FoundFlag = $True
# Est considéré qu'une seule application peut être rebuild d'une autre
                                            Break   
                                        }
                                        else {
                                            Write-output "Azure Managed Application $($ParseManagedApplication.Name) is NOT the rebuild for $CurrentApplicationName."                                            
                                        }
                                    }
                                }
                                else {
                                    #
                                    # Managed Application it NOT for rebuild purpose
                                    #
                                    Write-Output "Managed Application $($ParseManagedApplication.Name) is for rebuild purpose."
                                }
                            }
                            else {
                                Write-Output "Managed Application $($ParseManagedApplication.Name) is NOT related to Bastion."                                
                            }
                            If ($Rebuild_FoundFlag -eq $true)
                            {
                                #
                                # Managed Application to use for Rebuild purpose found, no need to parse more Managed Applications
                                #
                                Break
                            }
                        }
                        If ($Rebuild_FoundFlag -eq $true)
                        {
                            Write-Output "Initiating Rebuild process for $CurrentApplicationName with $($ParseManagedApplication.Name)."
                            #
                            # Searching for existing Key vault and Secrets
                            #
                            $checkForKeyVault = Get-AzKeyVault -ResourceGroupName $rgname -ErrorAction SilentlyContinue
                            If ($checkForKeyVault.Count -eq 1)
                            {
                                #
                                # Key Vault found in Resource group
                                #
                                Write-Output "KeyVault instance named $($checkForKeyVault.VaultName) found in resource Group name $RGName."
                                $Listsecrets = Get-AzKeyVaultSecret -VaultName $checkForKeyVault.VaultName -ErrorAction SilentlyContinue
                                if ([string]::IsNullOrEmpty($Listsecrets) -eq $False)
                                {
                                    #
                                    # Checking for secrets in Key Vault
                                    #
                                    if(($Listsecrets.name) -contains $LocalAdministratorPasswordSecretName)
                                    {
                                        Write-Output "Secret named $LocalAdministratorPasswordSecretName exists in Key Vault instance $($checkForKeyVault.VaultName)."
                                        if(($Listsecrets.name) -contains $LocalAdministratorUserNameSecretName)
                                        {
                                            Write-Output "Secret named $LocalAdministratorUserNameSecretName exists in Key Vault instance $($checkForKeyVault.VaultName)."

                                            if(($Listsecrets.name) -contains $VMOwnerSecretName)
                                            {
                                                Write-Output "Secret named $VMOwnerSecretName exists in Key Vault instance $($checkForKeyVault.VaultName)."
                                                #
                                                # Add items
                                                #

                                                $NewManagedApplication = Get-AzManagedApplicationDefinition -ResourceGroupName $ManagedApplicationRGName -Name $($ParseManagedApplication.Name)
                                                $NewManagedApplicationInstancename = $NewManagedApplication.ResourceName + $((New-Guid).Guid).Replace("-","")
                                                $NewManagedApplicationRGName = $NewManagedApplication.ResourceName + "-" + $((New-Guid).Guid).Replace("-","")
                                                $CurrentManagedApplicationParameters = $ManagedApplicationInstance.Properties.parameters
                                                #
                                                # Remove parameters we just extracted from Key Vault
                                                #
                                                $NewManagedApplicationParameters =  $CurrentManagedApplicationParameters | Select-Object -Property * -ExcludeProperty "AdminUserName"
                                                $NewManagedApplicationParameters =  $NewManagedApplicationParameters | Select-Object -Property * -ExcludeProperty "AdminPassword"
                                                $NewManagedApplicationParameters =  $NewManagedApplicationParameters | Select-Object -Property * -ExcludeProperty "vmOwner"
                                                $NewManagedApplicationParameters =  $NewManagedApplicationParameters | Select-Object -Property * -ExcludeProperty "secretnotbefore"
                                                $NewManagedApplicationParameters =  $NewManagedApplicationParameters | Select-Object -Property * -ExcludeProperty "expiration"

                                                [Hashtable]$DeploymentParameters = @{}
                                                $DeploymentParameters.windowsOSVersion = $NewManagedApplicationParameters.windowsOSVersion.value
                                                $DeploymentParameters.subnetName = $NewManagedApplicationParameters.subnetName.value
                                                $DeploymentParameters.vmNamePrefix = $NewManagedApplicationParameters.vmNamePrefix.value
                                                $DeploymentParameters.vmSize = $NewManagedApplicationParameters.vmSize.value
                                                $DeploymentParameters.diskType = $NewManagedApplicationParameters.diskType.value
                                                $DeploymentParameters.bastionStartPolicy = $NewManagedApplicationParameters.bastionStartPolicy.value
                                                $DeploymentParameters.bastionStopPolicy = $NewManagedApplicationParameters.bastionStopPolicy.value
                                                $DeploymentParameters.bastionRebuildPolicy = $NewManagedApplicationParameters.bastionRebuildPolicy.value
                                                $DeploymentParameters.chocolateypackage = $NewManagedApplicationParameters.chocolateypackage.value
                                                $DeploymentParameters.selfStartPolicy = $NewManagedApplicationParameters.selfStartPolicy.value
                                                $DeploymentParameters.selfStopPolicy =  $NewManagedApplicationParameters.selfStopPolicy.value
                                                $DeploymentParameters.selfRebootPolicy = $NewManagedApplicationParameters.selfRebootPolicy.value

                                                $DeploymentParameters.secretnotbefore = (get-date).ToFileTimeUtc()
                                                $DeploymentParameters.expiration = ((get-date).AddDays($BastionLifeDurationInDays)).tofiletimeutc()

#
# Considérer les multiples valeurs d'un secret et non le dernier
#
                                                $VMOwnerSecret = Get-AzKeyVaultSecret -VaultName $checkForKeyVault.VaultName  -Name $VMOwnerSecretName
                                                $LocalAdminUserSecret = Get-AzKeyVaultSecret -VaultName $checkForKeyVault.VaultName  -Name $LocalAdministratorUserNameSecretName
                                                $LocalAdminpasswordSecret = Get-AzKeyVaultSecret -VaultName $checkForKeyVault.VaultName  -Name $LocalAdministratorPasswordSecretName
                                                
                                                $DeploymentParameters.AdminUserName = $LocalAdminUserSecret.SecretValueText
                                                $DeploymentParameters.AdminPassword = $PWord = ConvertTo-SecureString -String $LocalAdminpasswordSecret.SecretValueText -AsPlainText -Force 
                                                $DeploymentParameters.vmOwner = $VMOwnerSecret.SecretValueText
                                                $JSONContent = $DeploymentParameters | ConvertTo-Json

# ManagedResourceGroupName => OK, on est dans le bon RG
# Resource Group Name => Error, il faut générer notre RG
# Manque plus que les paramètres et c'est OK
                                                New-AzManagedApplication -Name $NewManagedApplicationInstancename `
                                                    -Location $ManagedApplicationInstance.Location `
                                                    -Kind ServiceCatalog `
                                                    -ResourceGroupName $ManagedApplicationInstance.ResourceGroupName `
                                                    -ManagedApplicationDefinitionId $NewManagedApplication.ResourceId `
                                                    -ManagedResourceGroupName $NewManagedApplicationRGName `
                                                    -Parameter $JSONContent `
                                                    -Verbose
# bug ici sur les parameters, c'est pas le bon format
                                                    exit
#                                                     -Parameter @($JSONContent) `
    #  $ManagedApplicationInstance.Properties.applicationDefinitionId  # permettra de faire du déploiement en mode Cross-Subscription
#    New-AzManagedApplication -Name "myManagedApplication" `
#-ResourceGroupName myRG `
#-ManagedResourceGroupName myManagedRG `
#-ManagedApplicationDefinitionId "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/myRG/providers/Microsoft.Solutions/applicationDefinitions/myAppDef" `
#-Location eastus2euap `
#-Kind ServiceCatalog

                                            }
                                            else {
                                                Write-Output "Secret named $VMOwnerSecretName does NOT exists in Key Vault instance $($checkForKeyVault.VaultName). Unable to perform rebuild."
                                            }   
                                        }
                                        else {
                                            Write-Output "Secret named $LocalAdministratorUserNameSecretName does NOT exists in Key Vault instance $($checkForKeyVault.VaultName). Unable to perform rebuild."
                                        }
                                    }
                                    else {
                                        Write-Output "Secret named $LocalAdministratorPasswordSecretName does NOT exists in Key Vault instance $($checkForKeyVault.VaultName). Unable to perform rebuild."
                                    }
                                }
                                else {
                                    Write-Output "Unable to access Secrets from KeyVault instance $($checkForKeyVault.VaultName) located in resource group named $($checkForKeyVault.ResourceGroupName)."
                                }
                            }
                            else {
                                #
                                # No Key Vault or Multiple Key Vault found in Resource group
                                # 
                                Write-Output "No KeyVault or more than one KeyVault found in Resource Group name $rgname. Not possible to select witch one to use."
                            }
                            # Perform Desalocate of current application
                            Write-Output "Remove Managed Application $($ManagedApplicationInstance.name)"
                            Remove-AzManagedApplication -Id $ManagedApplicationInstance.ResourceId -Force # voir pour le placer en job
                            Write-Output "Managed Application $($ManagedApplicationInstance.name) removed successfully."

                        }
                        else {
                            #
                            # No rebuild possible for current Azure Managed Application
                            #
                            Write-Output "Unable to find suitable Azure Managed Application to perform rebuild for application $CurrentApplicationName. No rebuild possible."
                        }
                    }
                    else {
                        #
                        # Error, unable to perform rebuild operations because no Managed application exists in subscription
                        # OK
                        Write-Output "No Managed application found in Resource Group $ManagedApplicationRGName in subscription $SubscriptionName. Unable to perform rebuild operations."
                    }
                }
                else {
                    #
                    # Remove the Bastion Managed Application (Need to be performed as a job)
                    #
                    Write-Output "Remove Managed Application $($ManagedApplicationInstance.name)"
                    Remove-AzManagedApplication -Id $ManagedApplicationInstance.ResourceId -Force # voir pour le placer en job
                    Write-Output "Managed Application $($ManagedApplicationInstance.name) removed successfully."

                }

            }
            else {
                #
                # No need to rebuild this application
                # OK
                Write-Output "Managed Application expiration date not yet reached."
            }
            Write-Output "Managed application named $($ManagedApplicationInstance.name) processed."
        }
        else {
            Write-Output "Managed Application named $($ManagedApplicationInstance.name) is not related to Bastion."
        }
    }
    Write-Output "All Managed Application processed in subscription $SubscriptionName"
}
else {
    Write-Output "No Managed Application deployed in Subscription $SubscriptionName."
}
exit

                                                #
                                                #
                                                #
                                             #   https://stackoverflow.com/questions/36200749/how-do-you-add-more-property-values-to-a-custom-object
                                             exit
                                             #
                                             # Generate new values for parameters and add one for Snapshot
                                             #
                                             $test | Add-Member -Name "TEST" -MemberType NoteProperty -Value "Valur"
                                             # on approche
                                             $test | Add-Member -Name "TEST2" -MemberType NoteProperty -Value @{Type="String";Value="123"}
                                             $test | Add-Member -NotePropertyName "TEST3" -NotePropertyValue "TEST"
                                             $test = $test | Select-Object -Property * -ExcludeProperty "TEST2"
exit
                                             $Asset = New-Object -TypeName PSObject
                                             $d = [ordered]@{Name="Server30";System="Server Core";PSVersion="4.0"}
                                             $Asset | Add-Member -NotePropertyMembers $d -TypeName Asset
                                             $Asset | Get-Member
exit

$ourObject = New-Object -TypeName psobject
$PWord = ConvertTo-SecureString -String "P@sSwOrd" -AsPlainText -Force
$NewManagedApplicationParameters | Add-Member -MemberType NoteProperty -Name "TEST" -TypeName SecureString -Value $PWord

$ourObject | Add-Member -MemberType NoteProperty -Name "TEST" -TypeName SecureString -Value $PWord  # C'est good pour le secure string mais il faut maintenant un objet
$ourObject | Add-Member -MemberType NoteProperty -Name ComputerName -Value $computerInfo.Name
$ourObject | Add-Member -MemberType NoteProperty -Name OS -Value $osInfo.Caption
$ourObject | Add-Member -MemberType NoteProperty -Name 'OS Version' -Value $("$($osInfo.Version) Build $($osInfo.BuildNumber)")
$ourObject | Add-Member -MemberType NoteProperty -Name Domain -Value $computerInfo.Domain
$ourObject | Add-Member -MemberType NoteProperty -Name Workgroup -Value $computerInfo.Workgroup
$ourObject | Add-Member -MemberType NoteProperty -Name DomainJoined -Value $computerInfo.Workgroup
$ourObject | Add-Member -MemberType NoteProperty -Name Disks -Value $diskInfo
$ourObject | Add-Member -MemberType NoteProperty -Name AdminPasswordStatus -Value $adminPasswordStatus
$ourObject | Add-Member -MemberType NoteProperty -Name ThermalState -Value $thermalState
