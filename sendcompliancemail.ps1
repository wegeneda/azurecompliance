<#
    .SYNOPSIS
        Send Azure Policy Alerts and compliance state to subscription owner via email

    .DESCRIPTION
        Version: 1.0.2
  
    .NOTES
        This PowerShell script was developed to collect diagnostic settings options on Azure Ressources.

    .COMPONENT
        Requires Module AzureRM.Profile >= 5.8.3
        Requires Module AzureRM.PolicyInsights
        Requires Module AzureRM.Tags


    .LINK
#>

# Parameter set
param (
)

# Functions
function executeWithRetry {

    [CmdletBinding()]

   param(
   [Parameter(ValueFromPipeline,Mandatory)]$Command
   )

   $RetryDelay = 45
   $MaxRetries = 5
   $currentRetry = 0
   $success = $false
   $cmd = $Command.ToString()

   do {

       try {
           $res = & $Command           
           $success = $true
           return $res           
       }

       catch {
           $currentRetry++
           write-output "$vmId Error: attempt $currentRetry; command: [$cmd]; Exception: $($_.Exception.Message) $([System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId((get-date), [System.TimeZoneInfo]::Local.Id, 'W. Europe Standard Time'))"
           if ($currentRetry -gt $MaxRetries) {                
               write-output "$vmId ErrorStop: after $currentRetry attempts; failed command: [$cmd] $([System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId((get-date), [System.TimeZoneInfo]::Local.Id, 'W. Europe Standard Time'))";exit
           }
           else {
               Start-Sleep -s $RetryDelay
           }
       }
   } while (!$success);
}
# get azure api token function
function getOAuthToken {
    $AzureRMSubscription = (Get-AzureRmContext).Subscription
    $AzureRmProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $RMProfileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($AzureRmProfile)
    $OAuthToken = $RMProfileClient.AcquireAccessToken($AzureRMSubscription.TenantId)
    return $OAuthToken
}

# Connect to Azure
#<- Authentication
$connectionName = "AzureRunAsConnection"
$servicePrincipalConnection = executeWithRetry { Get-AutomationConnection -Name $connectionName -ErrorAction Stop }
# Logging in to Azure...
$connectionResult = executeWithRetry { Add-AzureRmAccount -ServicePrincipal -TenantId $servicePrincipalConnection.TenantId -ApplicationId $servicePrincipalConnection.ApplicationId -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint -ErrorAction Stop }
# Authentication ->

# local variables
$location = $env:temp # location will be used to store images and html content files during runtime
$StorageAccountName = Get-AutomationVariable -Name 'WeeklyComplianceNotificationMail_storageAccountName'
$StorageAccountKey = Get-AutomationVariable -Name 'WeeklyComplianceNotificationMail_storageAccountKey'
$contentContainerName = 'weeklycompliancenotificationmail'

# SMTP and mail variables 
$cred = Get-AutomationPSCredential -Name 'WeeklyComplianceNotificationMail_smtpUserCredential'
$SMTPServer = "smtp.sendgrid.net"
$From = "security@wegener.io"
$Subject = 'Azure Weekly Compliance Notification Mail'

# load files from storage account
try {
    $ctx = New-AzureStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $StorageAccountKey
    # download file to temp dir
    Get-AzureStorageBlob -Container $contentContainerName -Context $ctx | Get-AzureStorageBlobContent -Destination $location | Out-Null
}
catch {
    "ERR: Download files from Storage Account"
    $_.Exception.Message
    $_.Exception.ItemName
    break
}

# get REST API token
$OAuthToken = getOAuthToken

# get all enabled subscriptions
$allSubscriptions = Get-AzureRmSubscription | where {$_.State -eq 'Enabled'}

foreach ($s in $allSubscriptions) {
    try {
        # select subscription
        Select-AzureRmSubscription -SubscriptionId $s.SubscriptionId | Out-Null
        write-output "INFO: #########################################################################################################"
        write-output "INFO: Running policy compliance check for Subscription: $($s.Name)!"
        
   }
    catch {
        "ERR: Select subscription"
        $_.Exception.Message
        $_.Exception.ItemName
        continue
    }

    # get subscription owner gid and name of current subscription
    $subscriptionownergid_org = $null
    $subscriptionownername_org = $null
    $subscriptionownergid_org = Get-AzureRMRoleAssignment -RoleDefinitionName "owner" -IncludeClassicAdministrators  | Where RoleDefinitionName -like "owner"
     if ($subscriptionownergid_org) {
        $subscriptionownergid_final = ($subscriptionownergid_org.DisplayName).Replace("@.onmicrosoft.com", "")
        $subscriptionownername_org = Get-AzureRmADUser -UserPrincipalName $subscriptionownergid_org.DisplayName
        $subscriptionownername_final = $subscriptionownername_org.DisplayName
	$Recipient = (Get-AzureRmADUser -UserPrincipalName).UserPrincipalName
    } else {
        $subscriptionownergid_final = "n/a"
        $subscriptionownername_final = "n/a"
    }

    # get all facts id tags for all resource groups of current subscription
    $resourcegrouptags = $null
    $resourcegrouptags = (Get-AzureRmTag -Name "FACTS ID" -ErrorAction SilentlyContinue).Values.Name
    if (!$resourcegrouptags) {
        $resourcegrouptags = "Resource Group tags not set. Please set tags!"
    }

    # get policy compliance of current subscription
    $compliance = $null
    $compliance = Get-AzureRmPolicyStateSummary
    $policyAssignments = (Get-AzureRmPolicyStateSummary).PolicyAssignments

    $complianceObject = @()
    $nonCompliantResource = $null
    $nonCompliantPolicies = $null

    # get azure security center recommendations from Azure Resource Graph API
    $request = $null
    $query = $null
    $query = @"
{
"subscriptions": [
"$($s.Id)"
],
"query": "SecurityResources | where type == 'microsoft.security/assessments' | where subscriptionId == '$($s.Id)' | extend assessmentKey = name, resourceId = tolower(trim(' ',tostring(properties.resourceDetails.Id))), healthStatus = properties.status.code, displayName = properties.displayName | where healthStatus =~ 'unhealthy' | where displayName notcontains 'Siemens:' | summarize count() by tostring(displayName) | order by count_"
}
"@

    $Header = @{"Content-Type" = "application/json";"Authorization"=("Bearer {0}" -f $OAuthToken.AccessToken)}
    $getACSRecommendation = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2018-09-01-preview"
    $request = Invoke-RestMethod -Uri $getACSRecommendation -Method POST -Headers $Header -body $query
 
    $ascCompliance = @();
    for ($i = 0; $i -lt $request.data.rows.Count; $i++)
    { 
        $tempObject = New-Object PSObject -Property @{            
            Name                   = $request.data.rows[$i][0]
            FailedResources        = $request.data.rows[$i][1]
        }
        $ascCompliance += $tempObject;
    }
    
    if($compliance.Results.NonCompliantResources -ne 0 -or $ascCompliance) {
        
        # Load email body outline from file
        $body = $null
        $body = Get-Content "$location\htmlBody.txt" | Out-String

        #Creation of the 3 dynamic rows
        $body_SubscriptionOwnerRows = @()
        $subownerTableRow = Get-Content $location\Table0_Row_SubOwner.html

        $body_SubscriptionRows = @()
        $subTableRow = Get-Content $location\Table1_Row_SubId.html

        $body_AlertRows = @()
        $alertTableRow = Get-Content $location\Table2_Row_Alerts.html

        $body_ASCAlertRows = @()
        $ascTableRow = Get-Content $location\Table3_Row_ASC.html

        $body_ASCConfigRows = @()
        $ascConfigTableRow = Get-Content $location\Table4_Row_ASC_config.html

        # create alert array
        $complianceObject = @()

        #for each row in the compliance variable find the 3 elements you need: resource, resourcetype and compliance settings (name of the policy)
        foreach ($policyAssignment in $policyAssignments) {
     
         $assignment = Get-AzureRmPolicyAssignment -Id $policyAssignment.PolicyAssignmentId

         # Get type of assignment
         $policyType = $null
         if($assignment.Properties.policyDefinitionId -like "*/policySetDefinitions/*") {
            $policyType = "Initiative"
         } else {
            $policyType = "Policy"
         }

         # Get assignment scope

         $scope = $null
         $scopeType = $null
         if($policyAssignment.PolicyAssignmentId -like "*managementgroups*"){
            $string = $policyAssignment.PolicyAssignmentId
            $string = $string.Replace("/providers/microsoft.management/managementgroups/","")
            $scope = "MG: " + $string -replace '/.*'
            $scopeType = "MG"
         } else {
            $scope = $s.Name;
            $scopeType = "SN"
         }
     
         $tempObject = New-Object PSObject -Property @{            
                        Name                   = $assignment.Properties.displayName
                        Scope                  = $scope
                        Type                   = $policyType
                        Compliance             = 'Non-Compliant'
                        NonCompliantResources  = $policyAssignment.Results.NonCompliantResources
                        NonCompliantPolicies   = $policyAssignment.Results.NonCompliantPolicies}

            # Count non-compliant resources and policies
            $nonCompliantResource +=  $policyAssignment.Results.NonCompliantResources;
            $nonCompliantPolicies +=  $policyAssignment.Results.NonCompliantPolicies;
    
            # add list to object
            $complianceObject += $tempObject
        }
         # Here to be dynamical adding the rows
        $tmpRow = $null
		$body_AlertsRows = $null
        foreach ($al in $complianceObject)
        {
            $tmpRow = $alertTableRow
            $tmpRow = $tmpRow -replace '#NAME_PLACEHOLDER#', $al.Name

            if($al.Scope -like "*MG*") {
                $tmpRow = $tmpRow -replace '#scope.png#', 'mg.png'
            }else {
                $tmpRow = $tmpRow -replace '#scope.png#', 'sn.png'
            }

            if($al.Type -eq "Initiative") {
                $tmpRow = $tmpRow -replace '#type.png#', 'initiative.png'
            } else {
                $tmpRow = $tmpRow -replace '#type.png#', 'policy.png'
            }

            $tmpRow = $tmpRow -replace '#SCOPE_PLACEHOLDER#', $al.Scope
            $tmpRow = $tmpRow -replace '#TYPE_PLACEHOLDER#', $al.Type
            $tmpRow = $tmpRow -replace '#SETTING_PLACEHOLDER#', $al.Compliance
            $tmpRow = $tmpRow -replace '#NONCOMP_PLACEHOLDER#', $al.NonCompliantResources
            $tmpRow = $tmpRow -replace '#COMP_PLACEHOLDER#', $al.NonCompliantPolicies

    
            $body_AlertsRows += $tmpRow
        }

        # Substitute the dynamic row in the alerts table
        $body = $body -replace '#SEGNALAZIONIROWS_PLACEHOLDER#', $body_AlertsRows

        # create subscription overview table
        $tmpRow = $null
        $tmpRow = $subTableRow -replace '#SUBNAME_PLACEHOLDER#', $s.Name
        $tmpRow = $tmpRow -replace '#SUBID_PLACEHOLDER#', $s.Id
        $tmpRow = $tmpRow -replace '#SUBID_OVERALLCOMPLIANCE#', 'Non-Compliant'
        $tmpRow = $tmpRow -replace '#SUBID_NONCOMPLIANTPOLICIES#', $nonCompliantPolicies
        $tmpRow = $tmpRow -replace '#SUBID_NONCOMPLIANTRESOURCES#', $nonCompliantResource
        $body_SubscriptionRows += $tmpRow

        # Substitute the dynamic row in the subscription table
        $body = $body -replace '#SUBSCRIPTIONROWS_PLACEHOLDER#', $body_SubscriptionRows

        # create subscription owner table
        $tmpRow = $null
        $tmpRow = $subownerTableRow -replace '#SUBOWNERGID_PLACEHOLDER#', $subscriptionownergid_final
        $tmpRow = $tmpRow -replace '#SUBOWNERNAME_PLACEHOLDER#', $subscriptionownername_final
        $tmpRow = $tmpRow -replace '#FACTSID_PLACEHOLDER#', $resourcegrouptags
        $body_SubscriptionOwnerRows += $tmpRow

        # Substitute the dynamic row in the subscription owner table
        $body = $body -replace '#SUBSCRIPTIONOWNERROWS_PLACEHOLDER#', $body_SubscriptionOwnerRows
        
        # create asc recommendations table
        foreach ($r in $ascCompliance)
        {
            $tmpRow = $ascTableRow
            $tmpRow = $tmpRow -replace '#ASCNAME_PLACEHOLDER#', $r.Name
            $tmpRow = $tmpRow -replace '#ASCSETTING_PLACEHOLDER#', "Unhealthy"
            $tmpRow = $tmpRow -replace '#ASCNONCOMP_PLACEHOLDER#', $r.FailedResources

            $body_ASCAlertsRows += $tmpRow
        }

        # Substitute the dynamic row in the asc recommendation table
        $body = $body -replace '#ASCSEGNALAZIONIROWS_PLACEHOLDER#', $body_ASCAlertsRows

        # create asc config table
        $output = $null;
        $Header = @{"Content-Type" = "application/json";"Authorization"=("Bearer {0}" -f $OAuthToken.AccessToken)}
        $getACSWorkspaceSettings = "https://management.azure.com/subscriptions/$($s.SubscriptionId)/providers/Microsoft.Security/workspaceSettings?api-version=2017-08-01-preview"
        $output = Invoke-RestMethod -Uri $getACSWorkspaceSettings -Method GET -Headers $Header
        if($output.value) {
            $ACSWorkspaceSettings = ($output.value.properties.workspaceId).Split("/")[8]
        } else {
            $ACSWorkspaceSettings = "Default"
        }
 
        $Header = @{"Content-Type" = "application/json";"Authorization"=("Bearer {0}" -f $OAuthToken.AccessToken)}
        $getACSAutoProvisioningConfig = "https://management.azure.com/subscriptions/$($s.SubscriptionId)/providers/Microsoft.Security/autoProvisioningSettings/default?api-version=2017-08-01-preview"
        $output = Invoke-RestMethod -Uri $getACSAutoProvisioningConfig -Method GET -Headers $Header
        $ACSAutoProvisioningConfig = $output.properties.autoProvision
 
        $Header = @{"Content-Type" = "application/json";"Authorization"=("Bearer {0}" -f $OAuthToken.AccessToken)}
        $getACSPricing = "https://management.azure.com/subscriptions/$($s.SubscriptionId)/providers/Microsoft.Security/pricings?api-version=2018-06-01"
        $output = Invoke-RestMethod -Uri $getACSPricing -Method GET -Headers $Header
        $ACSPricing = @();
             foreach ($item in $output.value)
             {
                 $tempObject = New-Object PSObject -Property @{            
                                     Name                   = $item.Name
                                     PricingTier            = $item.properties.pricingTier}
 
                 $ACSPricing +=  $tempObject;
             }
         
        $tmpRow = $null
        $tmpRow = $ascConfigTableRow
        $tmpRow = $tmpRow -replace '#ASCONFIG_PLACEHOLDER#', "Log Analytics Workspace"
        $tmpRow = $tmpRow -replace '#ASCONFIGVALUE_PLACEHOLDER#', $ACSWorkspaceSettings
        if($ACSWorkspaceSettings) {$tmpRow = $tmpRow -replace 'warning.png', "ok.png"}
 
        $body_ASCConfigRows += $tmpRow
 
        $tmpRow = $ascConfigTableRow
        $tmpRow = $tmpRow -replace '#ASCONFIG_PLACEHOLDER#', "Autoprovisioning Mode"
        $tmpRow = $tmpRow -replace '#ASCONFIGVALUE_PLACEHOLDER#', $ACSAutoProvisioningConfig 
        if($ACSAutoProvisioningConfig -like "On") {$tmpRow = $tmpRow -replace 'warning.png', "ok.png"}
         
        $body_ASCConfigRows += $tmpRow
 
        foreach ($item in $ACSPricing) {
             $tmpRow = $ascConfigTableRow
             $tmpRow = $tmpRow -replace '#ASCONFIG_PLACEHOLDER#', "ASC License: $($item.Name)"
             $tmpRow = $tmpRow -replace '#ASCONFIGVALUE_PLACEHOLDER#', $item.PricingTier
             if($item.PricingTier -eq "Standard") {$tmpRow = $tmpRow -replace 'warning.png', "ok.png"}
             
             $body_ASCConfigRows += $tmpRow
        }
 
        # Substitute the dynamic row in the asc config table
        $body = $body -replace '#ASCSCONFIG_PLACEHOLDER#', $body_ASCConfigRows

        # define images in html body
        $images = @(
            "$location\policy.png",
            "$location\resource.png",
            "$location\image001.gif",
            "$location\image002.gif",
            "$location\image003.jpg",
            "$location\image004.gif",
            "$location\image005.png",
            "$location\image007.png",
            "$location\image010.png"
        )

        If($body -like "*initiative.png*")          {$images += "$location\initiative.png"}
        If($body -like "*mg.png*")                  {$images += "$location\mg.png"}
        If($body -like "*sn.png*")                  {$images += "$location\sn.png"}
        If($body -like "*ok.png*")                  {$images += "$location\ok.png"}
        If($body -like "*warning.png*")             {$images += "$location\warning.png"}

        write-output "INFO: Compliance check complete - preparing mail!"
         # Add attachments

        write-output "INFO: Creating mail object!"
        $MailClient = New-Object System.Net.Mail.SmtpClient $SMTPServer
        $MailClient.Credentials = $cred
        $MailClient.Port = 587
        $MailClient.EnableSsl = $true;

        $Message = New-Object System.Net.Mail.MailMessage
        $Message.IsBodyHTML = $true;
        $Message.To.Add($Recipient)
        $Message.From = $From
        $Message.Subject = $Subject
        $Message.body = $body

       
        # Create and send mail
        try { 
            $MailClient.Send($Message)
            write-output "INFO: Send mail!"
            write-output "INFO: Send policy compliance compliance mail for Subscription: $($s.Name) to $($recipient)!"
            write-output "INFO: #########################################################################################################"
        }    
        catch {
            "ERR: Send encrypted mail failed!"
            $_.Exception.Message
            $_.Exception.ItemName
            continue
        }
    }
    

    
}


