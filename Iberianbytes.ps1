function Get-NetworkInformation {
    $networkInterfaces = Get-NetAdapter
    $ipConfig = Get-NetIPAddress
    $dnsSettings = Get-DnsClientServerAddress
    $routingTable = Get-NetRoute
    return $networkInterfaces, $ipConfig, $dnsSettings, $routingTable
}

function Enumerate-NetworkShares {
    $shares = Get-WmiObject -Class Win32_Share
    $permissions = Get-WmiObject -Class Win32_LogicalShareSecuritySetting
    return $shares, $permissions
}

function Get-SystemInformation {
    $installedSoftware = Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor
    $registrySoftware = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object { $_.DisplayName } | Select-Object DisplayName, DisplayVersion, Publisher
    $registrySystem = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName" | Select-Object -Property *
    $installedServices = Get-Service
    return $installedSoftware, $registrySoftware, $registrySystem, $installedServices
}

function Get-UserInformation {
    $users = Get-LocalUser | Select-Object Name, LastLogon, PasswordLastSet, Enabled, Description, SID
    $sessions = Get-WmiObject Win32_ComputerSystem | Select-Object UserName
    return $users, $sessions
}

function Get-ADInformation {
    $domain = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
    $domainControllers = Get-ADDomainController -Filter *
    $sites = Get-ADReplicationSite -Filter *
    $trusts = Get-ADTrust -Filter *
    $domainUsers = Get-ADUser -Filter * -Properties *
    $groups = Get-ADGroup -Filter * -Properties *
    $groupPolicies = Get-GPO -All
    return $domain, $domainControllers, $sites, $trusts, $domainUsers, $groups, $groupPolicies
}

function Get-GroupPolicies {
    return Get-GPO -All | Select-Object DisplayName, Id, GPOStatus, CreationTime, ModificationTime
}

function Get-DomainPolicies {
    $domain = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
    $domainPolicy = Get-GPO -All | Where-Object { $_.DomainName -eq $domain -and $_.DisplayName -eq "Default Domain Policy" }
    $domainControllersPolicy = Get-GPO -All | Where-Object { $_.DomainName -eq $domain -and $_.DisplayName -eq "Default Domain Controllers Policy" }
    return $domainPolicy, $domainControllersPolicy
}

function Find-PasswordFiles {
    $passwordFiles = @(
        "C:\Windows\System32\config\SAM",
        "C:\Windows\System32\config\SYSTEM"
    )

    $foundFiles = @()
    foreach ($file in $passwordFiles) {
        if (Test-Path $file) {
            $foundFiles += $file
        }
    }

    return $foundFiles
}

function Show-Information {
    param (
        [string]$Title,
        [array]$Data
    )

    Write-Host ($Title + "`n")
    $Data | Format-Table -AutoSize
}

$networkInterfaces, $ipConfig, $dnsSettings, $routingTable = Get-NetworkInformation
Show-Information -Title "Network Interfaces" -Data $networkInterfaces
Show-Information -Title "IP Configuration" -Data $ipConfig
Show-Information -Title "DNS Settings" -Data $dnsSettings
Show-Information -Title "Routing Table" -Data $routingTable

$shares, $permissions = Enumerate-NetworkShares
Show-Information -Title "Network Shares" -Data $shares
Show-Information -Title "Share Permissions" -Data $permissions

$installedSoftware, $registrySoftware, $registrySystem, $installedServices = Get-SystemInformation
Show-Information -Title "Installed Software" -Data $installedSoftware
Show-Information -Title "Registry Software" -Data $registrySoftware
Show-Information -Title "Registry System" -Data $registrySystem
Show-Information -Title "Installed Services" -Data $installedServices

$users, $sessions = Get-UserInformation
Show-Information -Title "Local Users" -Data $users
Show-Information -Title "User Sessions" -Data $sessions

$domain, $domainControllers, $sites, $trusts, $domainUsers, $groups, $groupPolicies = Get-ADInformation
Show-Information -Title "Active Directory Domain: $domain" -Data $domainControllers
Show-Information -Title "Active Directory Sites" -Data $sites
Show-Information -Title "Trust Relationships" -Data $trusts
Show-Information -Title "Domain Users" -Data $domainUsers
Show-Information -Title "Domain Groups" -Data $groups
Show-Information -Title "Group Policies" -Data $groupPolicies

$passwordFiles = Find-PasswordFiles

if ($passwordFiles) {
    Write-Host "Password-related files found:`n"
    foreach ($file in $passwordFiles) {
        Write-Host $file
    }
} else {
    Write-Host "No password-related files found."
}

$groupPolicies = Get-GroupPolicies
Show-Information -Title "Group Policies" -Data $groupPolicies

$domainPolicy, $domainControllersPolicy = Get-DomainPolicies
Show-Information -Title "Domain Policy" -Data $domainPolicy
Show-Information -Title "Domain Controllers Policy" -Data $domainControllersPolicy
