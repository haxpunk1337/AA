# Windows Security Assessment Script

# Output file
$outputFile = "windows_security_assessment_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

# Utility functions
function Write-Output-And-Log {
    param([string]$message)
    Write-Output $message
    Add-Content -Path $outputFile -Value $message
}

function Write-Header {
    param([string]$header)
    Write-Output-And-Log ""
    Write-Output-And-Log "## $header"
    Write-Output-And-Log "-------------------"
}

# Print banner
Write-Output-And-Log "================================================="
Write-Output-And-Log " Windows Security Assessment"
Write-Output-And-Log "================================================="
Write-Output-And-Log ""
Write-Output-And-Log "Date: $(Get-Date)"
Write-Output-And-Log "Hostname: $env:COMPUTERNAME"
Write-Output-And-Log "Windows Version: $((Get-WmiObject -class Win32_OperatingSystem).Caption)"
Write-Output-And-Log ""

# Security check functions
function Check-WindowsDefender {
    Write-Header "Windows Defender Status"
    $defenderStatus = Get-MpComputerStatus
    if ($defenderStatus.AntivirusEnabled) {
        Write-Output-And-Log "✅ Windows Defender is enabled"
    } else {
        Write-Output-And-Log "❌ Windows Defender is disabled"
    }
}

function Check-Firewall {
    Write-Header "Firewall Status"
    $firewallStatus = Get-NetFirewallProfile
    if ($firewallStatus | Where-Object { $_.Enabled -eq $true }) {
        Write-Output-And-Log "✅ Firewall is enabled"
    } else {
        Write-Output-And-Log "❌ Firewall is disabled"
    }
}

function Check-UAC {
    Write-Header "User Account Control (UAC) Status"
    $uacStatus = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA"
    if ($uacStatus.EnableLUA -eq 1) {
        Write-Output-And-Log "✅ User Account Control (UAC) is enabled"
    } else {
        Write-Output-And-Log "❌ User Account Control (UAC) is disabled"
    }
}

function Check-WindowsUpdate {
    Write-Header "Windows Update Status"
    $updateStatus = Get-WmiObject -Class Win32_QuickFixEngineering | Sort-Object -Property InstalledOn -Descending | Select-Object -First 1
    Write-Output-And-Log "Last installed update: $($updateStatus.InstalledOn)"
}

function Check-BitLocker {
    Write-Header "BitLocker Status"
    $bitlockerStatus = Get-BitLockerVolume
    if ($bitlockerStatus | Where-Object { $_.VolumeStatus -eq "FullyEncrypted" }) {
        Write-Output-And-Log "✅ BitLocker is enabled and volumes are encrypted"
    } else {
        Write-Output-And-Log "❌ BitLocker is not fully enabled or volumes are not encrypted"
    }
}

function Check-RemoteDesktop {
    Write-Header "Remote Desktop Status"
    $rdpStatus = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections"
    if ($rdpStatus.fDenyTSConnections -eq 0) {
        Write-Output-And-Log "⚠️ Remote Desktop is enabled"
    } else {
        Write-Output-And-Log "✅ Remote Desktop is disabled"
    }
}

function Check-PowerShellExecution {
    Write-Header "PowerShell Execution Policy"
    $executionPolicy = Get-ExecutionPolicy
    Write-Output-And-Log "Current PowerShell Execution Policy: $executionPolicy"
}

function Check-SMBv1 {
    Write-Header "SMBv1 Status"
    $smbv1Status = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
    if ($smbv1Status.State -eq "Enabled") {
        Write-Output-And-Log "❌ SMBv1 is enabled"
    } else {
        Write-Output-And-Log "✅ SMBv1 is disabled"
    }
}

function Check-AdminShares {
    Write-Header "Administrative Shares Status"
    $adminShares = Get-WmiObject -Class Win32_Share | Where-Object { $_.Name -match '^[A-Z]\$' }
    if ($adminShares) {
        Write-Output-And-Log "⚠️ Administrative shares are enabled:"
        $adminShares | ForEach-Object { Write-Output-And-Log " - $($_.Name)" }
    } else {
        Write-Output-And-Log "✅ No administrative shares detected"
    }
}

function Check-LocalAdminGroup {
    Write-Header "Local Administrators Group"
    $adminGroup = Get-LocalGroupMember -Group "Administrators"
    Write-Output-And-Log "Members of the local Administrators group:"
    $adminGroup | ForEach-Object { Write-Output-And-Log " - $($_.Name)" }
}

function Check-MalwareProcesses {
    Write-Header "Known Malware Processes"
    $knownMalware = @("malware.exe", "trojan.exe", "keylogger.exe")
    $malwareFound = $false
    foreach ($process in $knownMalware) {
        if (Get-Process -Name $process -ErrorAction SilentlyContinue) {
            Write-Output-And-Log "❌ Potential malware process detected: $process"
            $malwareFound = $true
        }
    }
    if (-not $malwareFound) {
        Write-Output-And-Log "✅ No known malware processes detected"
    }
}

function Check-FileSharing {
    Write-Header "File Sharing Status"
    $sharingStatus = Get-WmiObject -Class Win32_Share
    if ($sharingStatus) {
        Write-Output-And-Log "⚠️ File sharing is enabled. Shared folders:"
        $sharingStatus | ForEach-Object { Write-Output-And-Log " - $($_.Name)" }
    } else {
        Write-Output-And-Log "✅ No file sharing detected"
    }
}

function Check-BrowserSavedPasswords {
    Write-Header "Browser Saved Passwords"
    $browsers = @("Chrome", "Firefox", "Edge")
    foreach ($browser in $browsers) {
        $profilePath = "$env:LOCALAPPDATA\$browser\User Data\Default"
        if (Test-Path $profilePath) {
            Write-Output-And-Log "⚠️ $browser profile found. Saved passwords may be present."
        }
    }
}

function Check-AppDataCredentials {
    Write-Header "Credentials in AppData"
    $sensitiveFiles = Get-ChildItem -Path $env:APPDATA -Recurse -File | Where-Object { $_.Name -match "password|credential|secret" }
    if ($sensitiveFiles) {
        Write-Output-And-Log "⚠️ Potential sensitive files found in AppData:"
        $sensitiveFiles | ForEach-Object { Write-Output-And-Log " - $($_.FullName)" }
    } else {
        Write-Output-And-Log "✅ No obvious credential files found in AppData"
    }
}

function Check-UnencryptedNetworkShares {
    Write-Header "Unencrypted Network Shares"
    $shares = Get-WmiObject -Class Win32_Share | Where-Object { $_.Type -eq 0 }
    if ($shares) {
        Write-Output-And-Log "⚠️ Unencrypted network shares found:"
        $shares | ForEach-Object { Write-Output-And-Log " - $($_.Name)" }
    } else {
        Write-Output-And-Log "✅ No unencrypted network shares detected"
    }
}

function Check-AutoRunPrograms {
    Write-Header "AutoRun Programs"
    $autoRuns = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    if ($autoRuns) {
        Write-Output-And-Log "AutoRun programs detected:"
        foreach ($item in $autoRuns.PSObject.Properties) {
            if ($item.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) {
                Write-Output-And-Log " - $($item.Name): $($item.Value)"
            }
        }
    } else {
        Write-Output-And-Log "✅ No AutoRun programs detected"
    }
}

function Check-UnsignedDrivers {
    Write-Header "Unsigned Drivers"
    $unsignedDrivers = Get-WindowsDriver -Online | Where-Object { $_.OriginalFileName -and (-not $_.Driver.Signed) }
    if ($unsignedDrivers) {
        Write-Output-And-Log "⚠️ Unsigned drivers detected:"
        $unsignedDrivers | ForEach-Object { Write-Output-And-Log " - $($_.OriginalFileName)" }
    } else {
        Write-Output-And-Log "✅ No unsigned drivers detected"
    }
}

function Check-InsecureProtocolUsage {
    Write-Header "Insecure Protocol Usage"
    $insecureProtocols = @("FTP", "HTTP", "Telnet")
    foreach ($protocol in $insecureProtocols) {
        $insecureServices = Get-Service | Where-Object { $_.Name -match $protocol }
        if ($insecureServices) {
            Write-Output-And-Log "⚠️ Insecure protocol services detected:"
            $insecureServices | ForEach-Object { Write-Output-And-Log " - $($_.Name)" }
        }
    }
    if (-not $insecureServices) {
        Write-Output-And-Log "✅ No insecure protocol services detected"
    }
}

function Check-SSHSessions {
    Write-Header "SSH Sessions"
    $sshSessions = Get-WmiObject -Query "SELECT * FROM Win32_Process WHERE Name='sshd.exe'"
    if ($sshSessions) {
        Write-Output-And-Log "⚠️ Active SSH sessions detected:"
        $sshSessions | ForEach-Object { Write-Output-And-Log " - PID: $($_.ProcessId)" }
    } else {
        Write-Output-And-Log "✅ No SSH sessions detected"
    }
}

function Check-RDPSessions {
    Write-Header "RDP Sessions"
    $rdpSessions = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName
    if ($rdpSessions) {
        Write-Output-And-Log "⚠️ Active RDP sessions detected:"
        $rdpSessions | ForEach-Object { Write-Output-And-Log " - $($_)" }
    } else {
        Write-Output-And-Log "✅ No RDP sessions detected"
    }
}

function Check-ApplicationSessions {
    Write-Header "Application Sessions"
    $applications = @("outlook.exe", "teams.exe", "slack.exe")
    foreach ($app in $applications) {
        $appSessions = Get-Process -Name $app -ErrorAction SilentlyContinue
        if ($appSessions) {
            Write-Output-And-Log "⚠️ Active sessions for $app detected:"
            $appSessions | ForEach-Object { Write-Output-And-Log " - PID: $($_.Id)" }
        }
    }
    if (-not $appSessions) {
        Write-Output-And-Log "✅ No sessions for monitored applications detected"
    }
}

function Check-PasswordPolicy {
    Write-Header "Password Policy"
    $passwordPolicy = Get-LocalUser | Select-Object Name, PasswordNeverExpires, PasswordChangeable
    Write-Output-And-Log "Password policy details:"
    $passwordPolicy | ForEach-Object { Write-Output-And-Log " - $($_.Name): Password Never Expires: $($_.PasswordNeverExpires), Password Changeable: $($_.PasswordChangeable)" }
}

function Check-EventLogs {
    Write-Header "Event Logs"
    $logNames = @("System", "Security", "Application")
    foreach ($logName in $logNames) {
        $logEntries = Get-WinEvent -LogName $logName -MaxEvents 10
        Write-Output-And-Log "Recent entries from $logName log:"
        $logEntries | ForEach-Object { Write-Output-And-Log " - $($_.TimeCreated): $($_.Message)" }
    }
}

function Check-AntiVirusSoftware {
    Write-Header "Anti-Virus Software"
    $antivirusSoftware = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -match "Antivirus" }
    if ($antivirusSoftware) {
        Write-Output-And-Log "⚠️ Anti-Virus software detected:"
        $antivirusSoftware | ForEach-Object { Write-Output-And-Log " - $($_.Name)" }
    } else {
        Write-Output-And-Log "✅ No Anti-Virus software detected"
    }
}

function Check-UserPermissions {
    Write-Header "User Permissions"
    $users = Get-LocalUser
    foreach ($user in $users) {
        $permissions = Get-LocalUser -Name $user.Name | Select-Object -ExpandProperty Description
        Write-Output-And-Log "Permissions for $($user.Name): $permissions"
    }
}

function Check-RemoteAccessTools {
    Write-Header "Remote Access Tools"
    $remoteTools = @("TeamViewer", "AnyDesk", "Chrome Remote Desktop")
    foreach ($tool in $remoteTools) {
        $toolProcesses = Get-Process -Name $tool -ErrorAction SilentlyContinue
        if ($toolProcesses) {
            Write-Output-And-Log "⚠️ Remote access tool $tool detected:"
            $toolProcesses | ForEach-Object { Write-Output-And-Log " - PID: $($_.Id)" }
        }
    }
    if (-not $toolProcesses) {
        Write-Output-And-Log "✅ No remote access tools detected"
    }
}

function Check-ExposedPorts {
    Write-Header "Exposed Ports"
    $exposedPorts = netstat -an | Select-String "LISTENING"
    if ($exposedPorts) {
        Write-Output-And-Log "⚠️ Exposed ports detected:"
        $exposedPorts | ForEach-Object { Write-Output-And-Log " - $_" }
    } else {
        Write-Output-And-Log "✅ No exposed ports detected"
    }
}

function Check-DisabledServices {
    Write-Header "Disabled Services"
    $disabledServices = Get-Service | Where-Object { $_.StartType -eq 'Disabled' }
    if ($disabledServices) {
        Write-Output-And-Log "⚠️ Disabled services detected:"
        $disabledServices | ForEach-Object { Write-Output-And-Log " - $($_.Name)" }
    } else {
        Write-Output-And-Log "✅ No disabled services detected"
    }
}

function Check-ActiveProcesses {
    Write-Header "Active Processes"
    $processes = Get-Process
    Write-Output-And-Log "Active processes:"
    $processes | ForEach-Object { Write-Output-And-Log " - $($_.Name) (PID: $($_.Id))" }
}

function Check-LocalUserAccounts {
    Write-Header "Local User Accounts"
    $localUsers = Get-LocalUser
    Write-Output-And-Log "Local user accounts and their statuses:"
    $localUsers | ForEach-Object { Write-Output-And-Log " - $($_.Name): Enabled: $($_.Enabled)" }
}

function Check-GroupPolicy {
    Write-Header "Group Policy"
    $groupPolicies = Get-GPO -All
    Write-Output-And-Log "Applied Group Policies:"
    $groupPolicies | ForEach-Object { Write-Output-And-Log " - $($_.DisplayName)" }
}

function Check-EnabledRemoteManagement {
    Write-Header "Enabled Remote Management"
    $remoteManagement = @("WinRM", "RemoteDesktop")
    foreach ($service in $remoteManagement) {
        $serviceStatus = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($serviceStatus) {
            Write-Output-And-Log "⚠️ Remote management service $service is enabled"
        }
    }
    if (-not $serviceStatus) {
        Write-Output-And-Log "✅ No remote management services detected"
    }
}

function Check-SharedFolders {
    Write-Header "Shared Folders"
    $sharedFolders = Get-WmiObject -Class Win32_Share
    Write-Output-And-Log "Shared folders:"
    $sharedFolders | ForEach-Object { Write-Output-And-Log " - $($_.Name): $($_.Path)" }
}

function Check-OpenFirewallPorts {
    Write-Header "Open Firewall Ports"
    $firewallRules = Get-NetFirewallRule | Get-NetFirewallPortFilter
    Write-Output-And-Log "Open firewall ports:"
    $firewallRules | ForEach-Object { Write-Output-And-Log " - Port: $($_.Port)" }
}

function Check-StartupItems {
    Write-Header "Startup Items"
    $startupItems = Get-CimInstance -ClassName Win32_StartupCommand
    Write-Output-And-Log "Startup items:"
    $startupItems | ForEach-Object { Write-Output-And-Log " - $($_.Name): $($_.Command)" }
}

function Check-ScheduledTasks {
    Write-Header "Scheduled Tasks"
    $tasks = Get-ScheduledTask
    Write-Output-And-Log "Scheduled tasks:"
    $tasks | ForEach-Object { Write-Output-And-Log " - $($_.TaskName): $($_.TaskPath)" }
}


function Check-ExternalDevices {
    Write-Header "External Devices"
    $usbDevices = Get-WmiObject -Query "SELECT * FROM Win32_DiskDrive WHERE DeviceID LIKE '%USB%'"
    Write-Output-And-Log "Connected USB devices:"
    $usbDevices | ForEach-Object { Write-Output-And-Log " - $($_.DeviceID)" }
}


# Run security checks
Check-WindowsDefender
Check-Firewall
Check-UAC
Check-WindowsUpdate
Check-BitLocker
Check-RemoteDesktop
Check-PowerShellExecution
Check-SMBv1
Check-AdminShares
Check-LocalAdminGroup
Check-MalwareProcesses
Check-FileSharing
Check-BrowserSavedPasswords
Check-AppDataCredentials
Check-UnencryptedNetworkShares
Check-AutoRunPrograms
Check-UnsignedDrivers
Check-InsecureProtocolUsage
Check-SSHSessions
Check-RDPSessions
Check-ApplicationSessions
Check-PasswordPolicy
Check-EventLogs
Check-AntiVirusSoftware
Check-UserPermissions
Check-RemoteAccessTools
Check-ExposedPorts
Check-DisabledServices
Check-ActiveProcesses
Check-LocalUserAccounts
Check-GroupPolicy
Check-EnabledRemoteManagement
Check-SharedFolders
Check-OpenFirewallPorts
Check-StartupItems
Check-ScheduledTasks
Check-ExternalDevices

Write-Output-And-Log "Assessment complete. Output saved to $outputFile."

