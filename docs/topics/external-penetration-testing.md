# External Penetration Testing

[← Home](../../README.md) · [Topic index](../INDEX.md)

## Contents

- [Domain Finding / Subdomain Enumeration](#domain-finding-subdomain-enumeration)
- [File Search / Metadata extraction](#file-search-metadata-extraction)
- [Scanner](#scanner)
- [Email Gathering](#email-gathering)
- [Check Email Accounts](#check-email-accounts)
- [Domain Auth + Exploitation](#domain-auth-exploitation)
- [Exchange RCE-exploits](#exchange-rce-exploits)
- [MobileIron RCE](#mobileiron-rce)

## Domain Finding / Subdomain Enumeration

- [aboul3la/Sublist3r](https://github.com/aboul3la/Sublist3r)
- [TheRook/subbrute](https://github.com/TheRook/subbrute)
- [michenriksen/aquatone](https://github.com/michenriksen/aquatone)
- [darkoperator/dnsrecon](https://github.com/darkoperator/dnsrecon)
- [fwaeytens/dnsenum](https://github.com/fwaeytens/dnsenum)
- [s0md3v/Striker](https://github.com/s0md3v/Striker) - + Scanner
- [leebaird/discover](https://github.com/leebaird/discover)
- [eldraco/domain_analyzer](https://github.com/eldraco/domain_analyzer) - more like an audit
- [subfinder/subfinder](https://github.com/subfinder/subfinder)
- [TypeError/domained](https://github.com/TypeError/domained)
- [SilverPoision/Rock-ON](https://github.com/SilverPoision/Rock-ON)

## File Search / Metadata extraction
- [dafthack/PowerMeta](https://github.com/dafthack/PowerMeta)
- [ElevenPaths/FOCA](https://github.com/ElevenPaths/FOCA)

## Scanner

- [vesche/scanless](https://github.com/vesche/scanless)
- [1N3/Sn1per](https://github.com/1N3/Sn1per)
- [DanMcInerney/pentest-machine](https://github.com/DanMcInerney/pentest-machine)
- [jaeles-project/jaeles](https://github.com/jaeles-project/jaeles) - The Swiss Army knife for automated Web Application Testing

## Email Gathering

- [leapsecurity/InSpy](https://github.com/leapsecurity/InSpy)
- [dchrastil/ScrapedIn](https://github.com/dchrastil/ScrapedIn)
- [SimplySecurity/SimplyEmail](https://github.com/SimplySecurity/SimplyEmail)
- [clr2of8/GatherContacts](https://github.com/clr2of8/GatherContacts)
- [s0md3v/Zen](https://github.com/s0md3v/Zen) - Find Emails of Github Users
- [m8r0wn/CrossLinked](https://github.com/m8r0wn/CrossLinked) - super fast emails via google/bing linkedin dorks
- [navisecdelta/EmailGen](https://github.com/navisecdelta/EmailGen) - A simple email generator that uses dorks on Bing to generate emails from LinkedIn Profiles.

## Check Email Accounts

- [megadose/holehe](https://github.com/megadose/holehe) - allows you to check if the mail is used on different sites like twitter, instagram and will retrieve information on sites with the forgotten password function.

## Domain Auth + Exploitation

- [nyxgeek/o365recon](https://github.com/nyxgeek/o365recon)
- [gremwell/o365enum](https://github.com/gremwell/o365enum) - Enumerate valid usernames from Office 365 using ActiveSync, Autodiscover v1, or office.com login page.
- [dafthack/MSOLSpray](https://github.com/dafthack/MSOLSpray) - A password spraying tool for Microsoft Online accounts (Azure/O365). The script logs if a user cred is valid, if MFA is enabled on the account, if a tenant doesn't exist, if a user doesn't exist, if the account is locked, or if the account is disabled.
- [sachinkamath/NTLMRecon](https://github.com/sachinkamath/NTLMRecon) - Tool to enumerate information from NTLM authentication enabled web endpoints
- [ustayready/fireprox](https://github.com/ustayready/fireprox) - rotate IP Adresses over AWS - Combine with MSOLSpray
- [True-Demon/raindance](https://github.com/True-Demon/raindance) - office 365 recon
- [dafthack/MailSniper](https://github.com/dafthack/MailSniper)
- [sensepost/ruler](https://github.com/sensepost/ruler)
- [Greenwolf/Spray](https://github.com/Greenwolf/Spray) - lockout Time integrated
- [nyxgeek/lyncsmash](https://github.com/nyxgeek/lyncsmash) - Lync Credential Finder
- [byt3bl33d3r/SprayingToolkit](https://github.com/byt3bl33d3r/SprayingToolkit) - Scripts to make password spraying attacks against Lync/S4B & OWA a lot quicker, less painful and more efficient
- [mdsecresearch/LyncSniper](https://github.com/mdsecresearch/LyncSniper) - Lync Credential Finder
- [3gstudent/easBrowseSharefile](https://github.com/3gstudent/easBrowseSharefile) - Use to browse the share file by eas(Exchange Server ActiveSync)
- [FSecureLABS/peas](https://github.com/FSecureLABS/peas) - PEAS is a Python 2 library and command line application for running commands on an ActiveSync server e.g. Microsoft Exchange.
- [snovvcrash/peas](https://github.com/snovvcrash/peas) - Modified version of PEAS client for offensive operations -  https://snovvcrash.rocks/2020/08/22/tuning-peas-for-fun-and-profit.html
- [RedLectroid/OutlookSend](https://github.com/RedLectroid/OutlookSend) - A C# tool to send emails through Outlook from the command line or in memory
- [nccgroup/Carnivore](https://github.com/nccgroup/Carnivore) - Tool for assessing on-premises Microsoft servers authentication such as ADFS, Skype, Exchange, and RDWeb
- [ricardojoserf/adfsbrute](https://github.com/ricardojoserf/adfsbrute) - A script to test credentials against Active Directory Federation Services (ADFS), allowing password spraying or bruteforce attacks.
- [nyxgeek/onedrive_user_enum](https://github.com/nyxgeek/onedrive_user_enum) - onedrive user enumeration - pentest tool to enumerate valid onedrive users
- [nyxgeek/AzureAD_Autologon_Brute](https://github.com/nyxgeek/AzureAD_Autologon_Brute) - Brute force attack tool for Azure AD Autologon/Seamless SSO - Source: https://arstechnica.com/information-technology/2021/09/new-azure-active-directory-password-brute-forcing-flaw-has-no-fix/
- [treebuilder/aad-sso-enum-brute-spray](https://github.com/treebuilder/aad-sso-enum-brute-spray) - POC of SecureWorks' recent Azure Active Directory password brute-forcing vuln
- [SecurityRiskAdvisors/msspray](https://github.com/SecurityRiskAdvisors/msspray) - Password attacks and MFA validation against various endpoints in Azure and Office 365
- [immunIT/TeamsUserEnum](https://github.com/immunIT/TeamsUserEnum) - User enumeration with Microsoft Teams API
- [knavesec/CredMaster](https://github.com/knavesec/CredMaster) - Refactored & improved CredKing password spraying tool, uses FireProx APIs to rotate IP addresses, stay anonymous, and beat throttling

## Exchange RCE-exploits

- [Airboi/CVE-2020-17144-EXP](https://github.com/Airboi/CVE-2020-17144-EXP) - Exchange2010 authorized RCE
- [Ridter/cve-2020-0688](https://github.com/Ridter/cve-2020-0688) - OWA Deserialisation RCE

## MobileIron RCE

- [httpvoid/CVE-Reverse](https://github.com/httpvoid/CVE-Reverse/tree/master/CVE-2020-15505)
