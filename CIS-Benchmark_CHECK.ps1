function cis11-12 #####1.1 & 1.2 Ensure that multi-factor authentication is enabled for all privileged and non-priveleged users (Scored)
{
    param
    (
        [array]$Users
    )

    Write-Host "1.1 & 1.2 Ensure that multi-factor authentication is enabled for all privileged and non-priveleged users (Scored)" -ForegroundColor Gray
    $all_ms_users_not_mfa = $Users | where {$_.StrongAuthenticationRequirements.count -eq 0}
if ($all_ms_users_not_mfa -eq 0) {Write-Host "`t1.1 & 1.2 Ensure that multi-factor authentication is enabled for all privileged and non-priveleged users (Scored) PASSED" -ForegroundColor Green}
    else {
        Write-Host "`t1.1 & 1.2 Ensure that multi-factor authentication is enabled for all privileged and non-priveleged users (Scored) FAILED" -ForegroundColor Red
        Write-Host "`tThere are $($all_ms_users_not_mfa.count) users without MFA:" -ForegroundColor Cyan
        foreach ($user in $all_ms_users_not_mfa)
            {
                Write-Host "`t`t$($user.DisplayName)" -ForegroundColor Cyan
            }
        }
}

function cis13 #####1.3 Ensure that there are no guest users (Scored)
{
    param
    (
        [array]$Users
    )
    Write-Host "1.3 Ensure that there are no guest users (Scored)" -ForegroundColor Gray
    $all_ms_guest_users = $Users | where {$_.UserType -eq "Guest"}
    if ($all_ms_guest_users -eq 0) {Write-Host "`t1.3 Ensure that there are no guest users (Scored) PASSED" -ForegroundColor Green}
    else {
        Write-Host "`t1.3 Ensure that there are no guest users (Scored) FAILED" -ForegroundColor Red
        Write-Host " `tThere are $($all_ms_guest_users.count) guest users:" -ForegroundColor Cyan
        foreach ($user in $all_ms_guest_users)
            {
                Write-Host "`t`t$($user.DisplayName)" -ForegroundColor Cyan
            }
        }
}

function cis123 #####1.23 Ensure that no custom subscription owner roles are created (Scored)
{
    param
    (
        [array]$roles
    )
    Write-Host "1.23 Ensure that no custom subscription owner roles are created (Scored)" -ForegroundColor Gray
    $all_custom_roles = $roles | where {$_.IsCustom -eq $true}
    if ($all_custom_roles.count -eq 0) {Write-Host "`t1.23 Ensure that no custom subscription owner roles are created (Scored) PASSED" -ForegroundColor Green}
    else {
        Write-Host "`t1.23 Ensure that no custom subscription owner roles are created (Scored) FAILED" -ForegroundColor Red
        Write-Host " `tThere are $($all_custom_roles.count) custom roles:" -ForegroundColor Cyan
        foreach ($role in $all_custom_roles)
            {
                Write-Host "`t`t$($role.DisplayName)" -ForegroundColor Cyan
            }
        }
}

function cis22-219 #####2.2 - 2.19 Ensure that Security Center requirements are met (Scored)
{
    param
    (
        [array]$content
    )
    Write-Host "2.2 - 2.19 Ensure that Security Center requirements are met (Scored)" -ForegroundColor Gray

    if ($content.value[0].properties.logCollection -eq "On") {Write-Host "`t2.2 Ensure that 'Automatic provisioning of monitoring agent' is set to 'On' (Scored) PASSED" -ForegroundColor Green}
        else {Write-Host "`t2.2 Ensure that 'Automatic provisioning of monitoring agent' is set to 'On' (Scored) FAILED" -ForegroundColor Red}
    if ($content.value[0].properties.recommendations.patch -eq "On") {Write-Host "`t2.3 Ensure that 'System updates' is set to 'On' (Scored) PASSED" -ForegroundColor Green}
        else {Write-Host "`t2.3 Ensure that 'System updates' is set to 'On' (Scored) FAILED" -ForegroundColor Red}
    if ($content.value[0].properties.recommendations.baseline -eq "On") {Write-Host "`t2.4 Ensure that 'Security Configurations' is set to 'On' (Scored) PASSED" -ForegroundColor Green}
        else {Write-Host "`t2.4 Ensure that 'Security Configurations' is set to 'On' (Scored) FAILED" -ForegroundColor Red}
    if ($content.value[0].properties.recommendations.antimalware -eq "On") {Write-Host "`t2.5 Ensure that 'Endpoint protection' is set to 'On' (Scored) PASSED" -ForegroundColor Green}
        else {Write-Host "`t2.5 Ensure that 'Endpoint protection' is set to 'On' (Scored) FAILED" -ForegroundColor Red}
    if ($content.value[0].properties.recommendations.diskEncryption -eq "On") {Write-Host "`t2.6 Ensure that 'Disk encryption' is set to 'On' (Scored) PASSED" -ForegroundColor Green}
        else {Write-Host "`t2.6 Ensure that 'Disk encryption' is set to 'On' (Scored)) FAILED" -ForegroundColor Red}
    if ($content.value[0].properties.recommendations.nsgs -eq "On") {Write-Host "`t2.7 Ensure that 'Network security groups' is set to 'On' (Scored) PASSED" -ForegroundColor Green}
        else {Write-Host "`t2.7 Ensure that 'Network security groups' is set to 'On' (Scored) FAILED" -ForegroundColor Red}
    if ($content.value[0].properties.recommendations.waf -eq "On") {Write-Host "`t2.8 Ensure that 'Web application firewall' is set to 'On' (Scored) PASSED" -ForegroundColor Green}
        else {Write-Host "`t2.8 Ensure that 'Web application firewall' is set to 'On' (Scored) FAILED" -ForegroundColor Red}
    if ($content.value[0].properties.recommendations.ngfw -eq "On") {Write-Host "`t2.9 Ensure that 'Next generation firewall' is set to 'On' (Scored) PASSED" -ForegroundColor Green}
        else {Write-Host "`t2.9 Ensure that 'Next generation firewall' is set to 'On' (Scored) FAILED" -ForegroundColor Red}
    if ($content.value[0].properties.recommendations.vulnerabilityAssessment -eq "On") {Write-Host "`t2.10 Ensure that 'Vulnerability assessment' is set to 'On' (Scored) PASSED" -ForegroundColor Green}
        else {Write-Host "`t2.10 Ensure that 'Vulnerability assessment' is set to 'On' (Scored) FAILED" -ForegroundColor Red}
    if ($content.value[0].properties.recommendations.storageEncryption -eq "On") {Write-Host "`t2.11 Ensure that 'Storage Encryption' is set to 'On' (Scored) PASSED" -ForegroundColor Green}
        else {Write-Host "`t2.11 Ensure that 'Storage Encryption' is set to 'On' (Scored) FAILED" -ForegroundColor Red}
    if ($content.value[0].properties.recommendations.jitNetworkAccess -eq "On") {Write-Host "`t2.12 Ensure that 'JIT Network Access' is set to 'On' (Scored) PASSED" -ForegroundColor Green}
        else {Write-Host "`t2.12 Ensure that 'JIT Network Access' is set to 'On' (Scored) FAILED" -ForegroundColor Red}
    if ($content.value[0].properties.recommendations.appWhitelisting -eq "On") {Write-Host "`t2.13 Ensure that 'Adaptive Application Controls' is set to 'On' (Scored) PASSED" -ForegroundColor Green}
        else {Write-Host "`t2.13 Ensure that 'Adaptive Application Controls' is set to 'On' (Scored) FAILED" -ForegroundColor Red}
    if ($content.value[0].properties.recommendations.sqlAuditing -eq "On") {Write-Host "`t2.14 Ensure that 'SQL auditing & Threat detection' is set to 'On' (Scored) PASSED" -ForegroundColor Green}
        else {Write-Host "`t2.14 Ensure that 'SQL auditing & Threat detection' is set to 'On' (Scored) FAILED" -ForegroundColor Red}
    if ($content.value[0].properties.recommendations.sqlTde -eq "On") {Write-Host "`t2.15 Ensure that 'SQL Encryption' is set to 'On' (Scored) PASSED" -ForegroundColor Green}
        else {Write-Host "`t2.15 Ensure that 'SQL Encryption' is set to 'On' (Scored) FAILED" -ForegroundColor Red}
    if ($content.value[0].properties.securityContactConfiguration.securityContactEmails.Count -ne "0") {Write-Host "`t2.16 Ensure that 'Security contact emails' is set (Scored) PASSED" -ForegroundColor Green}
        else {Write-Host "`t2.16 Ensure that 'Security contact emails' is set (Scored) FAILED" -ForegroundColor Red}
    if ($content.value[0].properties.securityContactConfiguration.securityContactPhone.Length -ge 8 ) {Write-Host "`t2.17 Ensure that security contact 'Phone number' is set (Scored) PASSED" -ForegroundColor Green}
        else {Write-Host "`t2.17 Ensure that security contact 'Phone number' is set (Scored) FAILED" -ForegroundColor Red}
    if ($content.value[0].properties.securityContactConfiguration.areNotificationsOn -eq $true) {Write-Host "`t2.18 Ensure that 'Send me emails about alerts' is set to 'On' (Scored) PASSED" -ForegroundColor Green}
        else {Write-Host "`t2.18 Ensure that 'Send me emails about alerts' is set to 'On' (Scored) FAILED" -ForegroundColor Red}
    if ($content.value[0].properties.securityContactConfiguration.sendToAdminOn -eq $true) {Write-Host "`t2.19 Ensure that 'Send email also to subscription owners' is set to 'On' (Scored) PASSED" -ForegroundColor Green}
        else {Write-Host "`t2.19 Ensure that 'Send email also to subscription owners' is set to 'On' (Scored) FAILED" -ForegroundColor Red}

}

function cis31 #####3.1 Ensure that 'Secure transfer required' is set to 'Enabled' (Scored)
{
    param
    (
        [array]$storage
    )
    Write-Host "3.1 Ensure that 'Secure transfer required' is set to 'Enabled' (Scored)" -ForegroundColor Gray
    [int]$nr_not_compliant_storage = 0
    $not_compliant_storages = @()
    foreach ($storage_account in $storage)
        {
            if ($storage_account.EnableHttpsTrafficOnly -eq $false) {
                $nr_not_compliant_storage ++
                $not_compliant_storages += $storage_account.StorageAccountName
            }
        }

    if ($nr_not_compliant_storage -eq 0) {Write-Host "`t3.1 Ensure that 'Secure transfer required' is set to 'Enabled' (Scored) PASSED" -ForegroundColor Green}
    else {
        Write-Host "`t3.1 Ensure that 'Secure transfer required' is set to 'Enabled' (Scored) FAILED" -ForegroundColor Red
        Write-Host " `tThere are $($not_compliant_storages.count) storage accounts without HTTPS enabled:" -ForegroundColor Cyan
        foreach ($name in $not_compliant_storages)
            {
                Write-Host "`t`t$name" -ForegroundColor Cyan
            }
        }
}

function cis32 #####3.2 Ensure that 'Storage service encryption' is set to Enabled for Blob Service (Scored)
{
    param
    (
        [array]$storage
    )
    Write-Host "3.2 Ensure that 'Storage service encryption' is set to Enabled for Blob Service (Scored)" -ForegroundColor Gray
    [int]$nr_not_compliant_storage = 0
    $not_compliant_storages = @()
    foreach ($storage_account in $storage)
        {
            if ($storage_account.Encryption.Services.Blob.Enabled -eq $false) {
                $nr_not_compliant_storage ++
                $not_compliant_storages += $storage_account.StorageAccountName
            }
        }

    if ($nr_not_compliant_storage -eq 0) {Write-Host "`t3.2 Ensure that 'Storage service encryption' is set to Enabled for Blob Service (Scored) PASSED" -ForegroundColor Green}
    else {
        Write-Host "`t3.2 Ensure that 'Storage service encryption' is set to Enabled for Blob Service (Scored) FAILED" -ForegroundColor Red
        Write-Host " `tThere are $($not_compliant_storages.count) storage accounts NOT encrypted:" -ForegroundColor Cyan
        foreach ($name in $not_compliant_storages)
            {
                Write-Host "`t`t$name" -ForegroundColor Cyan
            }
        }
}

function cis36 #####3.6 Ensure that 'Storage service encryption' is set to Enabled for File Service (Scored)
{
    param
    (
        [array]$storage
    )
    Write-Host "3.6 Ensure that 'Storage service encryption' is set to Enabled for File Service (Scored)" -ForegroundColor Gray
    [int]$nr_not_compliant_storage = 0
    $not_compliant_storages = @()
    foreach ($storage_account in $storage)
        {
            if ($storage_account.Encryption.Services.File.Enabled -eq $false) {
                $nr_not_compliant_storage ++
                $not_compliant_storages += $storage_account.StorageAccountName
            }
        }

    if ($nr_not_compliant_storage -eq 0) {Write-Host "`t3.6 Ensure that 'Storage service encryption' is set to Enabled for File Service (Scored) PASSED" -ForegroundColor Green}
    else {
        Write-Host "`t3.6 Ensure that 'Storage service encryption' is set to Enabled for File Service (Scored) FAILED" -ForegroundColor Red
        Write-Host " `tThere are $($not_compliant_storages.count) storage accounts NOT encrypted:" -ForegroundColor Cyan
        foreach ($name in $not_compliant_storages)
            {
                Write-Host "`t`t$name" -ForegroundColor Cyan
            }
        }
}

function cis37 #####3.7 Ensure that 'Public access level' is set to Private for blob containers (Scored)
{
    param
    (
        [array]$storage
    )
    Write-Host "3.7 Ensure that 'Public access level' is set to Private for blob containers (Scored)" -ForegroundColor Gray
    [int]$nr_not_compliant_containers = 0
    $not_compliant_containers = @()
    foreach ($storage_account in $storage)
        {
            $storage_key = (Get-AzureRmStorageAccountKey -ResourceGroupName $($storage_account.ResourceGroupName) -Name $($storage_account.StorageAccountName))[0].Value
            $storage_context = New-AzureStorageContext -StorageAccountName $($storage_account.StorageAccountName) -StorageAccountKey $storage_key
            $all_containers = Get-AzureStorageContainer -Context $storage_context
            foreach ($container in $all_containers) 
                {
                    if ($container.publicaccess -ne "Off") {
                        $nr_not_compliant_containers ++
                        $newobj = New-Object System.Object
                        $newobj | Add-Member -Type NoteProperty -name StorageName -value $storage_account.StorageAccountName
                        $newobj | Add-Member -Type NoteProperty -name ContainerName -value $container.Name

                        $not_compliant_containers += $newobj
                    }
                }
        }

    if ($nr_not_compliant_containers -eq 0) {Write-Host "`t3.7 Ensure that 'Public access level' is set to Private for blob containers (Scored) PASSED" -ForegroundColor Green}
    else {
        Write-Host "`t3.7 Ensure that 'Public access level' is set to Private for blob containers (Scored) FAILED" -ForegroundColor Red
        Write-Host " `tThere are $($not_compliant_containers.count) containers with public access:" -ForegroundColor Cyan
        foreach ($name in $not_compliant_containers)
            {
                Write-Host "`t`t$($name.StorageName) - $($name.ContainerName)" -ForegroundColor Cyan
            }
        }
}

function cis51 #####5.1 Ensure that a Log Profile exists (Scored)
{
    param
    (
        [array]$profiles
    )
    Write-Host "5.1 Ensure that a Log Profile exists (Scored)" -ForegroundColor Gray

    if ($profiles.count -ne 0) {Write-Host "`t5.1 Ensure that a Log Profile exists (Scored) PASSED" -ForegroundColor Green}
    else {
        Write-Host "`t5.1 Ensure that a Log Profile exists (Scored) FAILED" -ForegroundColor Red
        }  
}

function cis52 #####5.2 Ensure that Activity Log Retention is set 365 days or greater (Scored)
{
    param
    (
        [array]$profiles
    )
    Write-Host "5.2 Ensure that Activity Log Retention is set 365 days or greater (Scored)" -ForegroundColor Gray
    [int]$nr_not_compliant_profiles = 0
    $not_compliant_profiles = @()
    foreach ($profile in $profiles)
        {
            if (!($profile.RetentionPolicy.Days -eq 0 -or $profile.RetentionPolicy.Days -ge 365))
                {
                    $nr_not_compliant_profiles ++
                    $not_compliant_profiles += $profile
                }
        }

    if ($nr_not_compliant_profiles.count -eq 0) {Write-Host "`t5.2 Ensure that Activity Log Retention is set 365 days or greater (Scored) PASSED" -ForegroundColor Green}
    else {
        Write-Host "`t5.2 Ensure that Activity Log Retention is set 365 days or greater (Scored) FAILED" -ForegroundColor Red
        Write-Host " `tThere are $($not_compliant_profiles.count) log Profiles with retention policy less than 365 days:" -ForegroundColor Cyan
        foreach ($name in $not_compliant_profiles)
            {
                Write-Host "`t`t$($name.name)" -ForegroundColor Cyan
            }
        }
}

function cis53-512 #####5.3-5.12 Ensure existence of some Activity Log Alert (Scored)
{
    param
    (
        [array]$resource_groups,
        [string]$expression,
        [string]$cis_requirement
    )
    Write-Host $cis_requirement -ForegroundColor Gray
    $ErrorActionPreference= 'silentlycontinue'
    [int]$nr_not_compliant_rules = 0
    foreach ($rg in $resource_groups)
        {
            try {
                $content = az monitor activity-log alert list --resource-group $($rg.ResourceGroupName) --query [*].condition.allOf[*].equals
                for ($i = 0; $i -lt $($content.length); $i++) {
                    if ($content[$i] -match $expression) {$nr_not_compliant_rules++ }
                    }
                }
            catch {}
        }
    if ($nr_not_compliant_rules -ne 0) {Write-Host "`t$cis_requirement PASSED" -ForegroundColor Green}
    else {Write-Host "`t$cis_requirement FAILED" -ForegroundColor Red}
}

function cis513 #####5.13 Ensure that logging for Azure KeyVault is 'Enabled' (Scored)
{
    param
    (
        [array]$keyvaults
    )
    Write-Host "5.13 Ensure that logging for Azure KeyVault is 'Enabled' (Scored)" -ForegroundColor Gray
    $diagnostic_enabled = @()
    if ($keyvaults -ne $null)
        {
            foreach ($keyvault in $keyvaults)
                {
                    $diagnostic_enabled += Get-AzureRmDiagnosticSetting -ResourceId $keyvault.ResourceId
                }
            if ($diagnostic_enabled.count -eq $keyvaults.count -and $diagnostic_enabled -ne 0) {Write-Host "`t5.13 Ensure that logging for Azure KeyVault is 'Enabled' (Scored) PASSED" -ForegroundColor Green}
            else {Write-Host "`t5.13 Ensure that logging for Azure KeyVault is 'Enabled' (Scored) FAILED" -ForegroundColor Red}
        }
    else {Write-Host "`t5.13 Ensure that logging for Azure KeyVault is 'Enabled' (Scored) FAILED" -ForegroundColor Red}
}

function cis61-62 #####6.1-6.2 Ensure that RDP and SSH access is restricted from the internet (Scored)
{
    param
    (
        [array]$nsgs,
        [string]$port,
        [string]$protocol,
        [string]$direction,
        [string]$cis_requirement
    )
    Write-Host $cis_requirement -ForegroundColor Gray
    $source01 = "*"
    $source02 = "internet"
    $source03 = "0.0.0.0"
    [int]$non_compliant_rules = 0
    foreach ($nsg in $nsgs)
        {
            for ($i = 0; $i -lt $nsg.SecurityRules.Count; $i++)
                {
                    if (($nsg.SecurityRules[$i].DestinationPortRange -eq $port -or `
                        ($nsg.SecurityRules[$i].DestinationPortRange.split('-')[0] -le $port -and $nsg.SecurityRules[$i].DestinationPortRange.split('-')[1] -ge $port)) -and `
                        $nsg.SecurityRules[$i].protocol -eq $protocol -and ($nsg.SecurityRules[$i].SourceAddressPrefix -eq $source01 -or $nsg.SecurityRules[$i].SourceAddressPrefix -eq $source02 -or `
                        $nsg.SecurityRules[$i].SourceAddressPrefix -eq $source03) -and $nsg.SecurityRules[$i].direction -eq $direction) {$non_compliant_rules++}
                }
        }
    if ($non_compliant_rules -eq 0) {Write-Host "`t$cis_requirement PASSED" -ForegroundColor Green}
        else {
            Write-Host "`t$cis_requirement FAILED" -ForegroundColor Red
        }  
}

function cis64 #####6.4 Ensure that Network Security Group Flow Log retention period is 'greater than 90 days' (Scored)
{
    param
    (
        [array]$nsgs,
        [array]$networkwatchers,
        [string]$cis_requirement
    )
    Write-Host $cis_requirement -ForegroundColor Gray
    [int]$non_compliant_watchers = 0
    foreach ($nsg in $nsgs)
        {
            foreach ($netwatcher in $networkwatchers)
                {
                    if ($nsg.Location -eq $netwatcher.Location ) 
                        {
                            $retention_days = (Get-AzureRmNetworkWatcherFlowLogStatus -NetworkWatcher $netwatcher -TargetResourceId $nsg.Id).RetentionPolicy.days
                            if ($retention_days -lt 90) {$non_compliant_watchers ++}
                        }
                }
        }
    if ($non_compliant_watchers -eq 0) {Write-Host "`t$cis_requirement PASSED" -ForegroundColor Green}
    else {Write-Host "`t$cis_requirement FAILED" -ForegroundColor Red}
}

function cis65 #####6.5 Ensure that Network Watcher is 'Enabled' (Scored)
{
    param
    (
        [array]$networkwatchers,
        [array]$nw_locations,
        [string]$cis_requirement
    )
    Write-Host $cis_requirement -ForegroundColor Gray
    if ($all_networkwatchers.count -eq $nw_locations.Count) {Write-Host "`t$cis_requirement PASSED" -ForegroundColor Green}
    else {Write-Host "`t$cis_requirement FAILED" -ForegroundColor Red} 
}

function cis71 #####7.1 Ensure that VM agent is installed (Scored)
{
    param
    (
        [array]$all_vms,
        [string]$cis_requirement
    )
    Write-Host $cis_requirement -ForegroundColor Gray
    [int]$non_compliant_vms = 0
    foreach ($vm in $all_vms)
        {
            if ($vm.OSProfile.WindowsConfiguration.ProvisionVMAgent -ne $true) {$non_compliant_vms++}
        }
    if ($non_compliant_vms -eq 0) {Write-Host "`t$cis_requirement PASSED" -ForegroundColor Green}
    else {Write-Host "`t$cis_requirement FAILED" -ForegroundColor Red} 
}

function cis72 #####7.2 Ensure that 'OS disk' are encrypted (Scored)
{
    param
    (
        [array]$all_vms,
        [string]$cis_requirement
    )
    
    Write-Host $cis_requirement -ForegroundColor Gray
    [int]$non_compliant_vms = 0
    foreach ($vm in $all_vms)
        {
            $os_vol_encrypted = (Get-AzureRmVMDiskEncryptionStatus -ResourceGroupName $vm.ResourceGroupName -VMName $vm.Name).OsVolumeEncrypted
            if ($os_vol_encrypted -ne "Encrypted") {$non_compliant_vms++}
        }
    if ($non_compliant_vms -eq 0) {Write-Host "`t$cis_requirement PASSED" -ForegroundColor Green}
    else {Write-Host "`t$cis_requirement FAILED" -ForegroundColor Red} 
}

function cis73 #####7.3 Ensure that 'Data disks' are encrypted (Scored)
{
    param
    (
        [array]$all_vms,
        [string]$cis_requirement
    )
    Write-Host $cis_requirement -ForegroundColor Gray
    [int]$non_compliant_vms = 0
    foreach ($vm in $all_vms)
        {
            $data_vol_encrypted = (Get-AzureRmVMDiskEncryptionStatus -ResourceGroupName $vm.ResourceGroupName -VMName $vm.Name).DataVolumesEncrypted
            if ($data_vol_encrypted -ne "Encrypted") {$non_compliant_vms++}
        }

    if ($non_compliant_vms -eq 0) {Write-Host "`t$cis_requirement PASSED" -ForegroundColor Green}
    else {Write-Host "`t$cis_requirement FAILED" -ForegroundColor Red}
}

Connect-MsolService
Login-AzureRmAccount
$msol_users = Get-MsolUser
$all_roles = Get-AzureRmRoleDefinition
$all_storage_accounts = Get-AzureRmStorageAccount
az login

$azure_profile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
$azure_context = Get-AzureRmContext
$client_profile = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($azure_profile)
$token = $client_profile.AcquireAccessToken($azure_context.Subscription.TenantId)
$access_toke = "bearer $($token.AccessToken)"
$headers = @{'Authorization'="$access_toke";'Accept'='application/json'}
$subscription_id = (Get-AzureRmContext).Subscription.Id
$uri = "https://management.azure.com/subscriptions/$($subscription_id)/providers/microsoft.Security/policies?api-version=2015-06-01-preview"
$content = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
$all_log_profiles = Get-AzureRmLogProfile
$all_resource_groups = Get-AzureRmResourceGroup
$all_keyvaults = Get-AzureRmKeyVault
$all_nsg = Get-AzureRmNetworkSecurityGroup
$all_networkwatchers = Get-AzureRmNetworkWatcher
$nw_locations = (Get-AzureRmResourceProvider -ProviderNamespace Microsoft.Network).ResourceTypes.Where{($_.ResourceTypeName -eq 'networkwatchers')}.Locations
$all_vms = Get-AzureRmVM


#Chapter 1
cis11-12 $msol_users
cis13 $msol_users
cis123 $all_roles
#Chapter 2
cis22-219 $content
#Chapter 3
cis31 $all_storage_accounts
cis32 $all_storage_accounts
cis36 $all_storage_accounts
cis37 $all_storage_accounts
#Chapter 4
#Chapter 5
cis51 $all_log_profiles
cis52 $all_log_profiles
###cis53 $all_resource_groups "microsoft.authorization/policyassignments/write" "5.3 Ensure that Activity Log Alert exists for Create Policy Assignment (Scored)"
cis53-512 $all_resource_groups "Microsoft.Network/networkSecurityGroups/write" "5.4 Ensure that Activity Log Alert exists for Create or Update Network Security Group (Scored)"
cis53-512 $all_resource_groups "Microsoft.Network/networkSecurityGroups/delete" "5.5 Ensure that Activity Log Alert exists for Delete Network Security Group (Scored)"
cis53-512 $all_resource_groups "Microsoft.Network/networkSecurityGroups/securityRules/write" "5.6 Ensure that Activity Log Alert exists for Create or Update Network Security Group Rule (Scored)"
cis53-512 $all_resource_groups "Microsoft.Network/networkSecurityGroups/securityRules/delete" "5.7 Ensure that Activity Log Alert exists for Delete Network Security Group Rule (Scored)"
cis53-512 $all_resource_groups "Microsoft.Security/securitySolutions/write" "5.8 Ensure that Activity Log Alert exists for Create or Update Security Solution (Scored)"
cis53-512 $all_resource_groups "Microsoft.Security/securitySolutions/delete" "5.9 Ensure that Activity Log Alert exists for Delete Security Solution (Scored)"
cis53-512 $all_resource_groups "Microsoft.Sql/servers/firewallRules/write" "5.10 Ensure that Activity Log Alert exists for Create or Update SQL Server Firewall Rule (Scored)"
cis53-512 $all_resource_groups "Microsoft.Sql/servers/firewallRules/delete" "5.11 Ensure that Activity Log Alert exists for Delete SQL Server Firewall Rule (Scored)"
cis53-512 $all_resource_groups "Microsoft.Security/policies/write" "5.12 Ensure that Activity Log Alert exists for Update Security Policy (Scored)"
cis513 $all_keyvaults
#Chapter 6
cis61-62 $all_nsg "3389" "TCP" "Inbound" "6.1 Ensure that RDP access is restricted from the internet (Scored)"
cis61-62 $all_nsg "22" "TCP" "Inbound" "6.2 Ensure that SSH access is restricted from the internet (Scored)"
cis64 $all_nsg $all_networkwatchers "6.4 Ensure that Network Security Group Flow Log retention period is 'greater than 90 days' (Scored)"
cis65 $all_networkwatchers $nw_locations "6.5 Ensure that Network Watcher is 'Enabled' (Scored)"
#Chapter 7
cis71 $all_vms "7.1 Ensure that VM agent is installed (Scored)"
cis72 $all_vms "7.2 Ensure that 'OS disk' are encrypted (Scored)"
cis73 $all_vms "7.3 Ensure that 'Data disks' are encrypted (Scored)"
#Chapter 8


