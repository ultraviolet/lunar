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

Write-Output "Running with full privileges`n"

##########
#Users Scripts
##########

function Set-UserType {
    param (
        $User
    )

    Write-Output "Do (n)othing, make (a)dmin, make standard (u)ser, or (r)emove? "
    $key = Read-Host
    switch($key) {
        "n" {
             "`n";break}
        "a" {Add-LocalGroupMember -Group "Administrators" -Member $User.Name
             Write-Output "`n!!! Made $User an ADMINISTRATOR !!!"
             "`n";break}
        "u" {Remove-LocalGroupMember -Group "Administrators" -Member $User.Name
             Write-Output "`n!!! Made $User a STANDARD USER !!!"
             "`n";break}
        "r" {Write-Output "Are you sure? (y/n) "
             $key2 = Read-Host
             if ($key2 -eq "y") {
                Remove-LocalUser -Name $User.Name
                Write-Output "`n!!! REMOVED $User !!!"
             }
             else {Set-UserType -User $User}
             "`n";break}
        default {Write-Output "!!! Not an option !!!`n"
                 Set-UserType -User $User
                 ;break}
        }
}

# Edit users
$allusers = @(Get-LocalUser | Where-Object -Property Enabled -eq True | Where-Object -Property Name -NE $env:USERNAME)
$adminlist = @(Get-LocalGroupMember -Name "Administrators")
foreach ($user in $allusers) {
    "NAME: " + $user.Name
    if ($adminlist -like ("*"+ $user.Name)) {Write-Output "TYPE: ADMINISTRATOR`n"}
    else {Write-Output "TYPE: USER`n"}
    Set-UserType -User $user
}

# Force password change on next restart
# updates allusers
$allusers = @(Get-LocalUser | Where-Object -Property Enabled -eq True | Where-Object -Property Name -NE $env:USERNAME)
foreach ($user in $allusers) {
    Set-LocalUser -Name $user.name -PasswordNeverExpires $false
    net user "$user" /logonpasswordchg:yes
}

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