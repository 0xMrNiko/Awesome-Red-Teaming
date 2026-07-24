# Exfiltration

[← Home](../../README.md) · [Topic index](../INDEX.md)

## Contents

- [Credential harvesting Windows Specific](#credential-harvesting-windows-specific)
- [LSASS dumper / process dumper](#lsass-dumper-process-dumper)
- [Credential harvesting Linux Specific](#credential-harvesting-linux-specific)
- [Data Exfiltration - DNS/ICMP/Wifi Exfiltration](#data-exfiltration---dnsicmpwifi-exfiltration)
- [Git Specific](#git-specific)
- [Windows / Linux](#windows-linux)

## Credential harvesting Windows Specific

- [gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz)
- [GhostPack/SafetyKatz](https://github.com/GhostPack/SafetyKatz)
- [Flangvik/BetterSafetyKatz](https://github.com/Flangvik/BetterSafetyKatz) - Fork of SafetyKatz that dynamically fetches the latest pre-compiled release of Mimikatz directly from gentilkiwi GitHub repo, runtime patches signatures and uses SharpSploit DInvoke to PE-Load into memory.
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast) - Kerberoast with ACL abuse capabilities
- [Arvanaghi/SessionGopher](https://github.com/Arvanaghi/SessionGopher)
- [peewpw/Invoke-WCMDump](https://github.com/peewpw/Invoke-WCMDump)
- [tiagorlampert/sAINT](https://github.com/tiagorlampert/sAINT)
- [AlessandroZ/LaZagneForensic](https://github.com/AlessandroZ/LaZagneForensic) - remote lazagne
- [eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)
- [djhohnstein/SharpWeb](https://github.com/djhohnstein/SharpWeb) - Browser Creds gathering

https://github.com/moonD4rk/HackBrowserData - hack-browser-data is an open-source tool that could help you decrypt data[passwords|bookmarks|cookies|history] from the browser.

- [mwrlabs/SharpClipHistory](https://github.com/mwrlabs/SharpClipHistory) - ClipHistory feature get the last 25 copy paste actions
- [0x09AL/RdpThief](https://github.com/0x09AL/RdpThief) - extract live rdp logins
- [chrismaddalena/SharpCloud](https://github.com/chrismaddalena/SharpCloud) - Simple C# for checking for the existence of credential files related to AWS, Microsoft Azure, and Google Compute.
- [djhohnstein/SharpChromium](https://github.com/djhohnstein/SharpChromium) - .NET 4.0 CLR Project to retrieve Chromium data, such as cookies, history and saved logins.
- [rxwx/chlonium](https://github.com/rxwx/chlonium) - Chromium Cookie import / export tool
- [V1V1/SharpScribbles](https://github.com/V1V1/SharpScribbles) - ThunderFox for Firefox Credentials, SitkyNotesExtract for "Notes as passwords"
- [securesean/DecryptAutoLogon](https://github.com/securesean/DecryptAutoLogon) - Command line tool to extract/decrypt the password that was stored in the LSA by SysInternals AutoLogon
- [G0ldenGunSec/SharpSecDump](https://github.com/G0ldenGunSec/SharpSecDump) - .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py
- [EncodeGroup/Gopher](https://github.com/EncodeGroup/Gopher) - C# tool to discover low hanging fruits like SessionGopher
- [GhostPack/SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) - DPAPI Creds via C#
- [Hackndo/lsassy](https://github.com/Hackndo/lsassy)
- [aas-n/spraykatz](https://github.com/aas-n/spraykatz)
- [b4rtik/SharpKatz](https://github.com/b4rtik/SharpKatz) - C# porting of mimikatz sekurlsa::logonpasswords, sekurlsa::ekeys and lsadump::dcsync commands
- [login-securite/DonPAPI](https://github.com/login-securite/DonPAPI) - Dumping DPAPI credz remotely
- [Barbarisch/forkatz](https://github.com/Barbarisch/forkatz) - credential dump using foreshaw technique using SeTrustedCredmanAccessPrivilege
- [skelsec/pypykatz](https://github.com/skelsec/pypykatz) - Mimikatz implementation in pure Python

## LSASS dumper / process dumper

- [codewhitesec/HandleKatz](https://github.com/codewhitesec/HandleKatz) - PIC lsass dumper using cloned handles
- [m0rv4i/SafetyDump](https://github.com/m0rv4i/SafetyDump) - Dump stuff without touching disk
- [CCob/MirrorDump](https://github.com/CCob/MirrorDump) - Another LSASS dumping tool that uses a dynamically compiled LSA plugin to grab an lsass handle and API hooking for capturing the dump in memory
- [deepinstinct/LsassSilentProcessExit](https://github.com/deepinstinct/LsassSilentProcessExit) - Command line interface to dump LSASS memory to disk via SilentProcessExit
- [outflanknl/Dumpert](https://github.com/outflanknl/Dumpert) - dump lsass using direct system calls and API unhooking
- [cube0x0/MiniDump](https://github.com/cube0x0/MiniDump) - C# Lsass parser
- [b4rtik/SharpMiniDump](https://github.com/b4rtik/SharpMiniDump) - Create a minidump of the LSASS process from memory - using Dumpert
- [b4rtik/ATPMiniDump](https://github.com/b4rtik/ATPMiniDump) - Evade WinDefender ATP credential-theft
- [aas-n/spraykatz](https://github.com/aas-n/spraykatz) - remote procdump.exe, copy dump file to local system and pypykatz for analysis/extraction
- [jfmaes/SharpHandler](https://github.com/jfmaes/SharpHandler) - This project reuses open handles to lsass to parse or minidump lsass

## Credential harvesting Linux Specific

- [huntergregal/mimipenguin](https://github.com/huntergregal/mimipenguin)
- [n1nj4sec/mimipy](https://github.com/n1nj4sec/mimipy)
- [dirtycow/dirtycow.github.io](https://github.com/dirtycow/dirtycow.github.io)
- [mthbernardes/sshLooterC](https://github.com/mthbernardes/sshLooterC) - SSH Credential loot
- [blendin/3snake](https://github.com/blendin/3snake) - SSH / Sudo / SU Credential loot
- [0xmitsurugi/gimmecredz](https://github.com/0xmitsurugi/gimmecredz)
- [TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey) - Tool to extract Kerberos tickets from Linux kernel keys.

## Data Exfiltration - DNS/ICMP/Wifi Exfiltration

- [FortyNorthSecurity/Egress-Assess](https://github.com/FortyNorthSecurity/Egress-Assess)
- [p3nt4/Invoke-TmpDavFS](https://github.com/p3nt4/Invoke-TmpDavFS)
- [DhavalKapil/icmptunnel](https://github.com/DhavalKapil/icmptunnel)
- [iagox86/dnscat2](https://github.com/iagox86/dnscat2)
- [Arno0x/DNSExfiltrator](https://github.com/Arno0x/DNSExfiltrator)
- [spieglt/FlyingCarpet](https://github.com/spieglt/FlyingCarpet) - Wifi Exfiltration
- [SECFORCE/Tunna](https://github.com/SECFORCE/Tunna) - Tunna is a set of tools which will wrap and tunnel any TCP communication over HTTP
- [sysdream/chashell](https://github.com/sysdream/chashell)
- [no0be/DNSlivery](https://github.com/no0be/DNSlivery) - Easy files and payloads delivery over DNS
- [mhaskar/DNSStager](https://github.com/mhaskar/DNSStager) - Hide your payload in DNS
- [Flangvik/SharpExfiltrate](https://github.com/Flangvik/SharpExfiltrate) - Modular C# framework to exfiltrate loot over secure and trusted channels.

## Git Specific

- [dxa4481/truffleHog](https://github.com/dxa4481/truffleHog)
- [zricethezav/gitleaks](https://github.com/zricethezav/gitleaks)
- [adamtlangley/gitscraper](https://github.com/adamtlangley/gitscraper)


## Windows / Linux
- [AlessandroZ/LaZagne](https://github.com/AlessandroZ/LaZagne)
- [Dionach/PassHunt](https://github.com/Dionach/PassHunt)
- [vulmon/Vulmap](https://github.com/vulmon/Vulmap)
