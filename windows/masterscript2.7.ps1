##########
#Admin Privileges
##########

param([switch]$Elevated)

function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if ((Test-Admin) -eq $false)  {
    if ($elevated) {
        # tried to elevate, did not work, aborting
    } else {
        Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
    }
    exit
}

Write-Host "ADMIN ACCESS LEVEL ACQUIRED: Running with full privileges`n"

##########
# Pre-Config
##########

# Show hidden files, file extensions
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
Set-ItemProperty $key Hidden 1
Set-ItemProperty $key HideFileExt 0
Set-ItemProperty $key ShowSuperHidden 1
Stop-Process -processname explorer
Write-Host "Now showing hidden files`n"
Sleep 1

##########
# GPEDIT
##########

# DOWNLOAD FILES #
$client = New-Object System.Net.WebClient

# LGPO.exe
$client.DownloadFile(
    "https://drive.google.com/uc?export=download&id=19JKMJTwOBUTVuAg3cTTrGi6kla9x96_b&confirm=t&uuid=ea6597a5-0715-416f-a95e-cebfbcedd156&at=AB6BwCBP55rusHl6QL8c5-avCF5O:1698801290317",
    "C:\LGPO.exe")

# GPO 
$client.DownloadFile(
    "https://drive.google.com/uc?export=download&id=1Oh0l6LxabD5mxWgTYpNXiHPHgWKwWV1y",
    "C:\goodconfig.PolicyRules")

# Local Sec Pol
$client.DownloadFile(
    "https://drive.google.com/uc?export=download&id=1cXDjUybTvBWtZlYHRO0PSiYVp4ubD1iQ&confirm=t&uuid=fbabe190-ce5a-413f-b0d2-83493075d99e&at=AB6BwCDEzYf62HcylXVYO3GOGmzr:1698802823091",
    "C:\gensecpol.inf")

# Advanced Audit Pol
$client.DownloadFile(
    "https://drive.google.com/uc?export=download&id=1sSywSFnG_Csd3DsYRvMUNUlqG2AZdtGz",
    "C:\advauditpol.csv")
  

$anykey = Read-Host -Prompt "All files should be successfully downloaded. Press any key to continue..."

# APPLY CONFIG #

# Apply GPO
cmd /c "C:\LGPO.exe /p C:\goodconfig.PolicyRules /v"

# Apply Local Sec Pol
cmd /c "C:\LGPO.exe /s C:\gensecpol.inf /v"

# Apply Advanced Audit Pol
cmd /c "C:\LGPO.exe /a C:\advauditpol.csv /v"

# Enable firewall and apply settings
Write-Host "`nConfiguring firewall...`n"
netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
netsh advfirewall set allprofiles settings inboundusernotification disable
netsh advfirewall set allprofiles settings unicastresponsetomulticast disable

# Log config
netsh advfirewall set allprofiles logging allowedconnections enable
netsh advfirewall set allprofiles logging droppedconnections enable
netsh advfirewall set allprofiles logging maxfilesize 16384
netsh advfirewall set domainprofile logging filename "%systemroot%\system32\logfiles\firewall\domainfw.log"
netsh advfirewall set privateprofile logging filename "%systemroot%\system32\logfiles\firewall\privatefw.log"
netsh advfirewall set publicprofile logging filename "%systemroot%\system32\logfiles\firewall\publicfw.log"

# Make sure changes saved/applied
cmd /c "gpupdate /force"

$anykey = Read-Host -Prompt "All security policies should be updated. Press any key to continue..."

##########
#Users Scripts
##########

function Set-UserType {
    param (
        $User
    )

    $key = Read-Host -Prompt "Do (n)othing, make (a)dmin, make standard (u)ser, or (r)emove? "
    switch($key) {
        "n" {
             "`n";break}
        "a" {Add-LocalGroupMember -Group "Administrators" -Member $User.Name
             Write-Host "`n!!! Made $User an ADMINISTRATOR !!!"
             "`n";break}
        "u" {Remove-LocalGroupMember -Group "Administrators" -Member $User.Name
             Write-Host "`n!!! Made $User a STANDARD USER !!!"
             "`n";break}
        "r" {Write-Host "Are you sure? (y/n) "
             $key2 = Read-Host
             if ($key2 -eq "y") {
                Remove-LocalUser -Name $User.Name
                Write-Host "`n!!! REMOVED $User !!!"
             }
             else {Set-UserType -User $User}
             "`n";break}
        default {Write-Host "!!! Not an option !!!`n"
                 Set-UserType -User $User
                 ;break}
        }
}

# Edit users
$allusers = @(Get-LocalUser | Where-Object -Property Enabled -eq True | Where-Object -Property Name -NE $env:USERNAME)
$adminlist = @(Get-LocalGroupMember -Name "Administrators")
foreach ($user in $allusers) {
    "NAME: " + $user.Name
    if ($adminlist -like ("*"+ $user.Name)) {Write-Host "TYPE: ADMINISTRATOR`n"}
    else {Write-Host "TYPE: USER`n"}
    Set-UserType -User $user
}

# Force password change on next restart
# updates allusers
$allusers = @(Get-LocalUser | Where-Object -Property Enabled -eq True | Where-Object -Property Name -NE $env:USERNAME)
foreach ($user in $allusers) {
    Set-LocalUser -Name $user.name -PasswordNeverExpires $false
    net user "$user" /logonpasswordchg:yes
}

Write-Host "`nUser Configuration Completed`nServices to be configured next..."
Sleep 2

##########
# Services
##########

#
# ALWAYS DISABLE #
#

# Application Layer Gateway Service
Stop-Service -Name ALG -Force
Set-Service -Name ALG -StartupType Disabled

# Bluetooth Support Service
Stop-Service -Name bthserv -Force
Set-Service -Name bthserv -StartupType Disabled

# BranchCache
Stop-Service -Name PeerDistSvc -Force
Set-Service -Name PeerDistSvc -StartupType Disabled

# Certificate Propogate
Stop-Service -Name CertPropSvc -Force
Set-Service -Name CertPropSvc -StartupType Disabled

# Delivery Optimization
Stop-Service -Name DoSvc -Force
Set-Service -Name DoSvc -StartupType Disabled

# ICS
Stop-Service -Name SharedAccess -Force
Set-Service -Name SharedAccess -StartupType Disabled

# IP Helper
Stop-Service -Name iphlpsvc -Force
Set-Service -Name iphlpsvc -StartupType Disabled

# Microsoft iSCSI
Stop-Service -Name MSiSCSI -Force
Set-Service -Name MSiSCSI -StartupType Disabled

# Natural Authentication
Stop-Service -Name NaturalAuthentication -Force
Set-Service -Name NaturalAuthentication -StartupType Disabled

# NetTCP Port Sharing
Stop-Service -Name NetTcpPortSharing -Force
Set-Service -Name NetTcpPortSharing -StartupType Disabled

# Offline Files
Stop-Service -Name CscService -Force
Set-Service -Name CscService -StartupType Disabled

# Peer Name Resolution protocol
Stop-Service -Name PNRPsvc -Force
Set-Service -Name PNRPsvc -StartupType Disabled

# Peer Networking Grouping
Stop-Service -Name p2psvc -Force
Set-Service -Name p2psvc -StartupType Disabled

# Peer Networking Identity Manager
Stop-Service -Name p2pimsvc -Force
Set-Service -Name p2pimsvc -StartupType Disabled

# Plug and Play
Stop-Service -Name PlugPlay -Force
Set-Service -Name PlugPlay -StartupType Disabled

# Print Spooler
Stop-Service -Name Spooler -Force
Set-Service -Name Spooler -StartupType Disabled

# Printer Notifications
Stop-Service -Name PrintNotify -Force
Set-Service -Name PrintNotify -StartupType Disabled

# Remote Registry
Stop-Service -Name RemoteRegistry -Force
Set-Service -Name RemoteRegistry -StartupType Disabled

# Retail Demo Service
Stop-Service -Name RetailDemo -Force
Set-Service -Name RetailDemo -StartupType Disabled

# Routing and Remote Access
Stop-Service -Name RemoteAccess -Force
Set-Service -Name RemoteAccess -StartupType Disabled

# Secondary Logon
Stop-Service -Name seclogon -Force
Set-Service -Name seclogon -StartupType Disabled

# SharedPC Account Manager
Stop-Service -Name shpamsvc -Force
Set-Service -Name shpamsvc -StartupType Disabled

# SNMP Trap
Stop-Service -Name SNMPTRAP -Force
Set-Service -Name SNMPTRAP -StartupType Disabled

# Spatial Data Service
Stop-Service -Name SharedRealitySvc -Force
Set-Service -Name SharedRealitySvc -StartupType Disabled

# SSDP Discovery
Stop-Service -Name SSDPSRV -Force
Set-Service -Name SSDPSRV -StartupType Disabled

# UPnP
Stop-Service -Name upnphost -Force
Set-Service -Name upnphost -StartupType Disabled

# XBOX Services
Stop-Service -Name XboxGipSvc -Force
Set-Service -Name XboxGipSvc -StartupType Disabled
Stop-Service -Name XblAuthManager -Force
Set-Service -Name XblAuthManager -StartupType Disabled
Stop-Service -Name XblGameSave -Force
Set-Service -Name XblGameSave -StartupType Disabled
Stop-Service -Name XboxNetApiSvc -Force
Set-Service -Name XboxNetApiSvc -StartupType Disabled

#
# DEPENDS ON README #
# 

# Bitlocker Drive Encryption
Stop-Service -Name BDESVC -Force
Set-Service -Name BDESVC -StartupType Disabled

# Windows Media Player Network Sharing (Media Server)
Stop-Service -Name WMPNetworkSvc -Force
Set-Service -Name WMPNetworkSvc -StartupType Disabled

# RDP
Stop-Service -Name RasAuto -Force
Set-Service -Name RasAuto -StartupType Disabled
Stop-Service -Name RasMan -Force
Set-Service -Name RasMan -StartupType Disabled
Stop-Service -Name SessionEnv -Force
Set-Service -Name SessionEnv -StartupType Disabled
Stop-Service -Name TermService -Force
Set-Service -Name TermService -StartupType Disabled
Stop-Service -Name UmRdpService -Force
Set-Service -Name UmRdpService -StartupType Disabled

#
# RUNNING AND AUTOMATIC
#

# Windows Defender Firewall
Set-Service -Name mpssvc -StartupType Automatic
Start-Service -Name mpssvc

# Security Service
Set-Service -Name SecurityHealthService -StartupType Automatic
Start-Service -Name SecurityHealthService

# Security Center
Set-Service -Name wscsvc -StartupType Automatic
Start-Service -Name wscsvc

# Windows Defender Threat Protection
Set-Service -Name Sense -StartupType Automatic
Start-Service -Name Sense

# Windows Update
Set-Service -Name wuauserv -StartupType Automatic
Start-Service -Name wuauserv

# Windows Update Medic
Set-Service -Name WaaSMedicSvc -StartupType Automatic
Start-Service -Name WaaSMedicSvc

# Event Log
Set-Service -Name EventLog -StartupType Automatic
Start-Service -Name EventLog

# User Profile Service
Set-Service -Name ProfSvc -StartupType Automatic
Start-Service -Name ProfSvc

# Error Reporting Service
Set-Service -Name WerSvc -StartupType Automatic
Start-Service -Name WerSvc

# Windows Time
Set-Service -Name W32Time -StartupType Automatic
Start-Service -Name W32Time