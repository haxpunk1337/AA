#!/bin/bash

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Output file
OUTPUT_FILE="$(dirname "$0")/northernlight_security_assessment_$(date +%Y%m%d_%H%M%S).txt"

# Function to print and log
print_and_log() {
    echo -e "$1"
    echo -e "$1" >> "$OUTPUT_FILE"
}

# Function to print section headers
print_header() {
    print_and_log ""
    print_and_log "${CYAN}## $1${NC}"
    print_and_log "-------------------"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Ensure the `defaults` file exists before reading it
safe_defaults_read() {
    if [ -f "$1" ]; then
        /usr/bin/defaults read "$1" "$2" 2>/dev/null
    fi
}

# Print banner
print_banner() {
    print_and_log "${BLUE}=================================================${NC}"
    print_and_log "${BLUE} Northernlight Re IT Assessment${NC}"
    print_and_log "${BLUE}=================================================${NC}"
    print_and_log ""
    print_and_log "${YELLOW}macOS Security Assessment${NC}"
    print_and_log "${YELLOW}=========================${NC}"
    print_and_log ""
    print_and_log "${CYAN}Date: $(date)${NC}"
    print_and_log "${CYAN}Hostname: $(hostname)${NC}"
    print_and_log "${CYAN}macOS Version: $(/usr/bin/sw_vers -productVersion)${NC}"
    print_and_log ""
}

# Security check functions
check_filevault() {
    print_header "FileVault Status"
    if command_exists fdesetup && fdesetup status | /usr/bin/grep -q "FileVault is On"; then
        print_and_log "${GREEN}✅ FileVault is enabled${NC}"
    else
        print_and_log "${RED}❌ FileVault is disabled${NC}"
    fi
}

check_firewall() {
    print_header "Firewall Status"
    if /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | /usr/bin/grep -q "enabled"; then
        print_and_log "${GREEN}✅ Firewall is enabled${NC}"
    else
        print_and_log "${RED}❌ Firewall is disabled${NC}"
    fi
}

check_sip() {
    print_header "System Integrity Protection Status"
    if command_exists csrutil && csrutil status 2>/dev/null | /usr/bin/grep -q "enabled"; then
        print_and_log "${GREEN}✅ System Integrity Protection is enabled${NC}"
    else
        print_and_log "${RED}❌ System Integrity Protection is disabled or not supported${NC}"
    fi
}

check_gatekeeper() {
    print_header "Gatekeeper Status"
    if /usr/sbin/spctl --status | /usr/bin/grep -q "assessments enabled"; then
        print_and_log "${GREEN}✅ Gatekeeper is enabled${NC}"
    else
        print_and_log "${RED}❌ Gatekeeper is disabled${NC}"
    fi
}

check_software_update() {
    print_header "Software Update Status"
    /usr/sbin/softwareupdate -l 2>/dev/null | /usr/bin/grep -q "No new software available"
    if [ $? -eq 0 ]; then
        print_and_log "${GREEN}✅ System is up to date${NC}"
    else
        print_and_log "${YELLOW}⚠️ Software updates are available${NC}"
    fi
}

check_password_policy() {
    print_header "Password Requirements"
    pwpolicy_output=$(pwpolicy -getaccountpolicies 2>/dev/null)
    if echo "$pwpolicy_output" | grep -q "policyAttributePassword matches"; then
        print_and_log "${GREEN}✅ Password policy is configured${NC}"
        print_and_log "$(echo "$pwpolicy_output" | grep "policyAttributePassword matches" | sed 's/^/ /')"
    else
        print_and_log "${RED}❌ No password policy configured${NC}"
    fi
}

check_auto_login() {
    print_header "Automatic Login"
    if defaults read /Library/Preferences/com.apple.loginwindow.plist autoLoginUser &>/dev/null; then
        print_and_log "${RED}❌ Automatic login is enabled${NC}"
    else
        print_and_log "${GREEN}✅ Automatic login is disabled${NC}"
    fi
}

check_screensaver_password() {
    print_header "Screen Saver Password"
    if defaults read com.apple.screensaver askForPassword | grep -q "1"; then
        print_and_log "${GREEN}✅ Screen saver password is enabled${NC}"
    else
        print_and_log "${RED}❌ Screen saver password is disabled${NC}"
    fi
}

check_remote_login() {
    print_header "Remote Login (SSH) Status"
    if systemsetup -getremotelogin | grep -q "On"; then
        print_and_log "${RED}❌ Remote Login (SSH) is enabled${NC}"
    else
        print_and_log "${GREEN}✅ Remote Login (SSH) is disabled${NC}"
    fi
}

check_guest_account() {
    print_header "Guest Account Status"
    if dscl . -read /Users/Guest UserShell | grep -q "/usr/bin/false"; then
        print_and_log "${GREEN}✅ Guest account is disabled${NC}"
    else
        print_and_log "${RED}❌ Guest account is enabled${NC}"
    fi
}

check_find_my_mac() {
    print_header "Find My Mac Status"
    if defaults read /Library/Preferences/com.apple.FindMyMac.plist | grep -q "FMMEnabled = 1"; then
        print_and_log "${GREEN}✅ Find My Mac is enabled${NC}"
    else
        print_and_log "${YELLOW}⚠️ Find My Mac is disabled${NC}"
    fi
}

check_auto_app_updates() {
    print_header "Automatic App Updates"
    if defaults read /Library/Preferences/com.apple.commerce AutoUpdate | grep -q "1"; then
        print_and_log "${GREEN}✅ Automatic app updates are enabled${NC}"
    else
        print_and_log "${YELLOW}⚠️ Automatic app updates are disabled${NC}"
    fi
}

check_xprotect() {
    print_header "XProtect Status"
    if [ -e "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.plist" ]; then
        print_and_log "${GREEN}✅ XProtect is enabled${NC}"
        xprotect_version=$(defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist Version)
        print_and_log " XProtect version: $xprotect_version"
    else
        print_and_log "${RED}❌ XProtect is disabled or not found${NC}"
    fi
}

check_time_machine() {
    print_header "Time Machine Backup"
    if tmutil destinationinfo &>/dev/null; then
        print_and_log "${GREEN}✅ Time Machine is configured${NC}"
        print_and_log "$(tmutil destinationinfo | grep "Name" | sed 's/^/ /')"
    else
        print_and_log "${YELLOW}⚠️ Time Machine is not configured${NC}"
    fi
}

check_filevault_recovery_key() {
    print_header "FileVault Recovery Key"
    if fdesetup hasPersonalRecoveryKey | grep -q "true"; then
        print_and_log "${GREEN}✅ FileVault recovery key is set${NC}"
    else
        print_and_log "${YELLOW}⚠️ FileVault recovery key is not set${NC}"
    fi
}

check_secure_keyboard_entry() {
    print_header "Secure Keyboard Entry in Terminal"
    if defaults read -app Terminal SecureKeyboardEntry | grep -q "1"; then
        print_and_log "${GREEN}✅ Secure Keyboard Entry in Terminal is enabled${NC}"
    else
        print_and_log "${YELLOW}⚠️ Secure Keyboard Entry in Terminal is disabled${NC}"
    fi
}

check_bluetooth_status() {
    print_header "Bluetooth Status"
    if defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState | grep -q "1"; then
        print_and_log "${YELLOW}⚠️ Bluetooth is enabled${NC}"
    else
        print_and_log "${GREEN}✅ Bluetooth is disabled${NC}"
    fi
}

check_sharing_services() {
    print_header "Sharing Services"
    sharing_status=$(sharing -l)
    if [ -z "$sharing_status" ]; then
        print_and_log "${GREEN}✅ No sharing services are enabled${NC}"
    else
        print_and_log "${YELLOW}⚠️ The following sharing services are enabled:${NC}"
        print_and_log "$sharing_status"
    fi
}

check_firmware_password() {
    print_header "Firmware Password"
    if /usr/sbin/firmwarepasswd -check | grep -q "Password Enabled: Yes"; then
        print_and_log "${GREEN}✅ Firmware password is set${NC}"
    else
        print_and_log "${YELLOW}⚠️ Firmware password is not set${NC}"
    fi
}

check_secure_boot() {
    print_header "Secure Boot Status"
    if csrutil authenticated-root status 2>/dev/null | grep -q "enabled"; then
        print_and_log "${GREEN}✅ Secure Boot is enabled${NC}"
    else
        print_and_log "${YELLOW}⚠️ Secure Boot status could not be determined (may not be applicable)${NC}"
    fi
}

check_auto_login_items() {
    print_header "Automatic macOS Login Items"
    login_items=$(osascript -e 'tell application "System Events" to get the name of every login item')
    if [ -z "$login_items" ]; then
        print_and_log "${GREEN}✅ No automatic login items found${NC}"
    else
        print_and_log "${YELLOW}⚠️ The following automatic login items were found:${NC}"
        print_and_log "$(echo "$login_items" | sed 's/^/ /')"
    fi
}

check_ntp_status() {
    print_header "Network Time Protocol Status"
    if systemsetup -getusingnetworktime | grep -q "On"; then
        print_and_log "${GREEN}✅ Network Time Protocol is enabled${NC}"
    else
        print_and_log "${YELLOW}⚠️ Network Time Protocol is disabled${NC}"
    fi
}

check_sudo_config() {
    print_header "Sudo Configuration"
    if grep -q "^[^#].*NOPASSWD" /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
        print_and_log "${RED}❌ NOPASSWD directive found in sudo configuration${NC}"
    else
        print_and_log "${GREEN}✅ No NOPASSWD directive found in sudo configuration${NC}"
    fi
}

check_unsigned_kexts() {
    print_header "Unsigned Kernel Extensions"
    unsigned_kexts=$(kextstat | grep -v "com.apple" | awk '{print $6}')
    if [ -z "$unsigned_kexts" ]; then
        print_and_log "${GREEN}✅ No unsigned kernel extensions found${NC}"
    else
        print_and_log "${YELLOW}⚠️ The following unsigned kernel extensions were found:${NC}"
        print_and_log "$(echo "$unsigned_kexts" | sed 's/^/ /')"
    fi
}

check_secure_empty_trash() {
    print_header "Secure Empty Trash"
    if defaults read com.apple.finder EmptyTrashSecurely | grep -q "1"; then
        print_and_log "${GREEN}✅ Secure Empty Trash is enabled${NC}"
    else
        print_and_log "${YELLOW}⚠️ Secure Empty Trash is disabled${NC}"
    fi
}

check_stealth_mode() {
    print_header "Stealth Mode"
    if /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode | grep -q "enabled"; then
        print_and_log "${GREEN}✅ Stealth mode is enabled${NC}"
    else
        print_and_log "${YELLOW}⚠️ Stealth mode is disabled${NC}"
    fi
}

check_gatekeeper_quarantine() {
    print_header "Gatekeeper Quarantine Events"
    quarantine_events=$(sqlite3 ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 "SELECT COUNT(*) FROM LSQuarantineEvent")
    print_and_log "${BLUE}Number of quarantine events: $quarantine_events${NC}"
}

check_cleartext_passwords() {
    print_header "Cleartext Passwords in Configuration Files"
    config_files=$(find /etc /Users -name "*.conf" -o -name "*.cfg" -o -name "*.ini" 2>/dev/null)
    password_found=$(grep -i "password" $config_files 2>/dev/null)
    if [ -z "$password_found" ]; then
        print_and_log "${GREEN}✅ No cleartext passwords found in common configuration files${NC}"
    else
        print_and_log "${RED}❌ Potential cleartext passwords found in configuration files:${NC}"
        print_and_log "$(echo "$password_found" | sed 's/^/ /')"
    fi
}

check_insecure_https() {
    print_header "Insecure HTTPS Implementation"
    insecure_https=$(find /Applications -name "Info.plist" -exec plutil -p {} \; | grep -i "NSAppTransportSecurity" | grep -i "NSAllowsArbitraryLoads.*true")
    if [ -z "$insecure_https" ]; then
        print_and_log "${GREEN}✅ No apps with insecure HTTPS implementation found${NC}"
    else
        print_and_log "${YELLOW}⚠️ Apps with potentially insecure HTTPS implementation:${NC}"
        print_and_log "$(echo "$insecure_https" | sed 's/^/ /')"
    fi
}

check_world_readable_files() {
    print_header "World-Readable Sensitive Files"
    sensitive_files=$(find /etc /Users -perm -004 \( -name "*password*" -o -name "*secret*" -o -name "*key*" \) 2>/dev/null)
    if [ -z "$sensitive_files" ]; then
        print_and_log "${GREEN}✅ No world-readable sensitive files found${NC}"
    else
        print_and_log "${RED}❌ World-readable sensitive files found:${NC}"
        print_and_log "$(echo "$sensitive_files" | sed 's/^/ /')"
    fi
}

check_weak_ssh_config() {
    print_header "Weak SSH Configurations"
    weak_ssh=$(grep -i "PermitRootLogin yes" /etc/ssh/sshd_config 2>/dev/null)
    if [ -z "$weak_ssh" ]; then
        print_and_log "${GREEN}✅ No weak SSH configurations found${NC}"
    else
        print_and_log "${RED}❌ Weak SSH configuration found: Root login is permitted${NC}"
    fi
}

check_unencrypted_backups() {
    print_header "Unencrypted Time Machine Backups"
    unencrypted_backups=$(tmutil destinationinfo | grep -i "Encrypted: No")
    if [ -z "$unencrypted_backups" ]; then
        print_and_log "${GREEN}✅ All Time Machine backups are encrypted${NC}"
    else
        print_and_log "${YELLOW}⚠️ Unencrypted Time Machine backups found:${NC}"
        print_and_log "$(echo "$unencrypted_backups" | sed 's/^/ /')"
    fi
}

check_shell_history() {
    print_header "Cleartext Passwords in Shell History"
    history_files=$(find /Users -name ".*_history" 2>/dev/null)
    passwords_in_history=$(grep -i "password" $history_files 2>/dev/null)
    if [ -z "$passwords_in_history" ]; then
        print_and_log "${GREEN}✅ No cleartext passwords found in shell history files${NC}"
    else
        print_and_log "${RED}❌ Potential cleartext passwords found in shell history:${NC}"
        print_and_log "$(echo "$passwords_in_history" | sed 's/^/ /')"
    fi
}

check_keychain_settings() {
    print_header "Insecure Keychain Settings"
    keychain_timeout=$(security show-keychain-info 2>&1 | grep "no-timeout")
    if [ -z "$keychain_timeout" ]; then
        print_and_log "${GREEN}✅ Keychain is set to lock after inactivity${NC}"
    else
        print_and_log "${YELLOW}⚠️ Keychain is set to never lock${NC}"
    fi
}

check_plist_passwords() {
    print_header "Cleartext Passwords in Property List Files"
    plist_files=$(find /Library /Users -name "*.plist" 2>/dev/null)
    passwords_in_plist=$(grep -i "password" $plist_files 2>/dev/null)
    if [ -z "$passwords_in_plist" ]; then
        print_and_log "${GREEN}✅ No cleartext passwords found in property list files${NC}"
    else
        print_and_log "${RED}❌ Potential cleartext passwords found in property list files:${NC}"
        print_and_log "$(echo "$passwords_in_plist" | sed 's/^/ /')"
    fi
}

check_safari_settings() {
    print_header "Insecure Safari Settings"
    safari_settings=$(defaults read com.apple.Safari 2>/dev/null | grep -E "AutoFillPasswords|AutoFillCreditCardData")
    if [ -z "$safari_settings" ]; then
        print_and_log "${GREEN}✅ Safari AutoFill for passwords and credit cards is disabled${NC}"
    else
        print_and_log "${YELLOW}⚠️ Safari has potentially insecure AutoFill settings:${NC}"
        print_and_log "$(echo "$safari_settings" | sed 's/^/ /')"
    fi
}

check_log_files() {
    print_header "Cleartext Sensitive Information in Log Files"
    log_files=$(find /var/log -type f 2>/dev/null)
    sensitive_in_logs=$(grep -i -E "password|secret|key" $log_files 2>/dev/null)
    if [ -z "$sensitive_in_logs" ]; then
        print_and_log "${GREEN}✅ No cleartext sensitive information found in log files${NC}"
    else
        print_and_log "${YELLOW}⚠️ Potential sensitive information found in log files:${NC}"
        print_and_log "$(echo "$sensitive_in_logs" | sed 's/^/ /')"
    fi
}

check_known_malware() {
    print_header "Known Malware Processes"
    known_malware=("MacKeeper" "MacDefender" "MacSecurity" "MacProtector")
    malware_found=false
    for malware in "${known_malware[@]}"; do
        if pgrep -i "$malware" > /dev/null; then
            print_and_log "${RED}❌ Potential malware detected: $malware${NC}"
            malware_found=true
        fi
    done
    if ! $malware_found; then
        print_and_log "${GREEN}✅ No known malware processes detected${NC}"
    fi
}

check_suspicious_connections() {
    print_header "Suspicious Outbound Connections"
    suspicious_connections=$(netstat -an | grep ESTABLISHED | grep -E ':22|:443|:1080|:8080' | grep -v '127.0.0.1')
    if [ -z "$suspicious_connections" ]; then
        print_and_log "${GREEN}✅ No suspicious outbound connections detected${NC}"
    else
        print_and_log "${YELLOW}⚠️ Suspicious outbound connections found:${NC}"
        print_and_log "$(echo "$suspicious_connections" | sed 's/^/ /')"
    fi
}

check_stored_sessions() {
    print_header "Stored Application Sessions"
    stored_sessions=$(find ~/Library/Saved\ Application\ State -type d -name "*.savedState")
    if [ -z "$stored_sessions" ]; then
        print_and_log "${GREEN}✅ No stored application sessions found${NC}"
    else
        print_and_log "${YELLOW}⚠️ Stored application sessions found:${NC}"
        print_and_log "$(echo "$stored_sessions" | sed 's/^/ /')"
    fi
}

check_browser_passwords() {
    print_header "Cleartext Passwords in Browser Data"
    browser_data_dirs=("~/Library/Application Support/Google/Chrome/Default" "~/Library/Application Support/Firefox/Profiles/*.default")
    cleartext_passwords=$(grep -r -i "password" "${browser_data_dirs[@]}" 2>/dev/null)
    if [ -z "$cleartext_passwords" ]; then
        print_and_log "${GREEN}✅ No cleartext passwords found in browser data${NC}"
    else
        print_and_log "${RED}❌ Potential cleartext passwords found in browser data:${NC}"
        print_and_log "$(echo "$cleartext_passwords" | sed 's/^/ /')"
    fi
}

check_ssh_keys() {
    print_header "Unauthorized SSH Keys"
    ssh_keys=$(find ~/.ssh -name "id_*" ! -name "*.pub")
    if [ -z "$ssh_keys" ]; then
        print_and_log "${GREEN}✅ No unauthorized SSH keys found${NC}"
    else
        print_and_log "${YELLOW}⚠️ SSH keys found. Please verify if they are authorized:${NC}"
        print_and_log "$(echo "$ssh_keys" | sed 's/^/ /')"
    fi
}

check_cron_jobs() {
    print_header "Suspicious Cron Jobs"
    suspicious_crons=$(crontab -l 2>/dev/null | grep -E "curl|wget|nc|bash.*\||sh.*\||python.*http")
    if [ -z "$suspicious_crons" ]; then
        print_and_log "${GREEN}✅ No suspicious cron jobs detected${NC}"
    else
        print_and_log "${RED}❌ Suspicious cron jobs found:${NC}"
        print_and_log "$(echo "$suspicious_crons" | sed 's/^/ /')"
    fi
}

check_safari_passwords() {
    print_header "Safari Saved Passwords"
    safari_passwords=$(security find-generic-password -ga "Safari" 2>&1 | grep "password:")
    if [ -z "$safari_passwords" ]; then
        print_and_log "${GREEN}✅ No saved passwords found in Safari${NC}"
    else
        print_and_log "${YELLOW}⚠️ Saved passwords found in Safari. Consider using a password manager${NC}"
        print_and_log "Number of saved passwords: $(echo "$safari_passwords" | wc -l)"
    fi
}

check_firefox_passwords() {
    print_header "Firefox Saved Passwords"
    firefox_profile=$(find ~/Library/Application\ Support/Firefox/Profiles/*.default-release -type d)
    if [ -z "$firefox_profile" ]; then
        print_and_log "${GREEN}✅ No Firefox profile found${NC}"
    else
        logins_json="$firefox_profile/logins.json"
        if [ -f "$logins_json" ]; then
            password_count=$(grep -c '"encryptedPassword"' "$logins_json")
            print_and_log "${YELLOW}⚠️ Firefox has saved passwords. Consider using a password manager${NC}"
            print_and_log "Number of saved passwords: $password_count"
        else
            print_and_log "${GREEN}✅ No saved passwords found in Firefox${NC}"
        fi
    fi
}

check_reverse_shell() {
    print_header "Reverse Shell Connections"
    suspicious_connections=$(netstat -antup 2>/dev/null | grep ESTABLISHED | grep -E 'bash|sh|nc|python|perl|ruby')
    if [ -z "$suspicious_connections" ]; then
        print_and_log "${GREEN}✅ No suspicious reverse shell connections detected${NC}"
    else
        print_and_log "${RED}❌ Potential reverse shell connections found:${NC}"
        print_and_log "$(echo "$suspicious_connections" | sed 's/^/ /')"
    fi
}

check_privilege_escalation() {
    print_header "Privilege Escalation Attempts"
    suid_files=$(find / -perm -4000 -type f 2>/dev/null)
    if [ -z "$suid_files" ]; then
        print_and_log "${GREEN}✅ No unexpected SUID files found${NC}"
    else
        print_and_log "${YELLOW}⚠️ SUID files found (potential privilege escalation vector):${NC}"
        print_and_log "$(echo "$suid_files" | sed 's/^/ /')"
    fi
}

check_unusual_processes() {
    print_header "Unusual Processes"
    unusual_processes=$(ps aux | grep -E 'nc|netcat|ncat|socat|mkfifo|mknod' | grep -v grep)
    if [ -z "$unusual_processes" ]; then
        print_and_log "${GREEN}✅ No unusual processes detected${NC}"
    else
        print_and_log "${RED}❌ Unusual processes found:${NC}"
        print_and_log "$(echo "$unusual_processes" | sed 's/^/ /')"
    fi
}

check_network_connections() {
    print_header "Suspicious Network Connections"
    suspicious_connections=$(netstat -antup 2>/dev/null | grep -E ':4444|:1337|:9001')
    if [ -z "$suspicious_connections" ]; then
        print_and_log "${GREEN}✅ No suspicious network connections detected${NC}"
    else
        print_and_log "${RED}❌ Suspicious network connections found:${NC}"
        print_and_log "$(echo "$suspicious_connections" | sed 's/^/ /')"
    fi
}

check_hidden_files() {
    print_header "Hidden Files in Unusual Locations"
    hidden_files=$(find /tmp /var/tmp /dev/shm -name ".*" -type f 2>/dev/null)
    if [ -z "$hidden_files" ]; then
        print_and_log "${GREEN}✅ No hidden files found in unusual locations${NC}"
    else
        print_and_log "${YELLOW}⚠️ Hidden files found in unusual locations:${NC}"
        print_and_log "$(echo "$hidden_files" | sed 's/^/ /')"
    fi
}

check_malware() {
    print_header "Malware Check"
    
    # List of common malware file paths
    malware_paths=(
        "/Library/Little Snitch"
        "/Library/Application Support/Malwarebytes"
        "/Library/Preferences/com.malwarebytes.antimalware.plist"
        "/Library/Application Support/Symantec"
        "/Library/Preferences/com.symantec.symantec endpoint protection.plist"
    )
    
    malware_found=false
    for path in "${malware_paths[@]}"; do
        if [ -e "$path" ]; then
            print_and_log "${RED}❌ Potential malware detected: $path${NC}"
            malware_found=true
        fi
    done
    
    if ! $malware_found; then
        print_and_log "${GREEN}✅ No known malware indicators found${NC}"
    fi
}

check_passwords_in_memory() {
    print_header "Passwords in Memory"
    
    # Use strings command to search for password-like patterns in memory
    memory_passwords=$(sudo strings /dev/mem 2>/dev/null | grep -E 'password|passwd|pwd' | sort | uniq)
    
    if [ -n "$memory_passwords" ]; then
        print_and_log "${RED}❌ Potential passwords found in memory:${NC}"
        print_and_log "$(echo "$memory_passwords" | sed 's/^/ /')"
    else
        print_and_log "${GREEN}✅ No obvious passwords found in memory${NC}"
    fi
}

check_keychain_security() {
    print_header "Keychain Security"
    
    # Check if keychain is locked
    if security show-keychain-info 2>&1 | grep -q "lock-on-sleep"; then
        print_and_log "${GREEN}✅ Keychain is set to lock on sleep${NC}"
    else
        print_and_log "${YELLOW}⚠️ Keychain may not be set to lock on sleep${NC}"
    fi
    
    # Check for any keychain items with weak encryption
    weak_items=$(security dump-keychain | grep -B 2 "kSecAttrAccessible=kSecAttrAccessibleAlways")
    if [ -n "$weak_items" ]; then
        print_and_log "${RED}❌ Keychain items with weak encryption found:${NC}"
        print_and_log "$(echo "$weak_items" | sed 's/^/ /')"
    else
        print_and_log "${GREEN}✅ No keychain items with weak encryption found${NC}"
    fi
}


# Main function
main() {
    print_banner
    check_filevault
    check_firewall
    check_sip
    check_gatekeeper
    check_software_update
    check_password_policy
    check_auto_login
    check_screensaver_password
    check_remote_login
    check_guest_account
    check_find_my_mac
    check_auto_app_updates
    check_xprotect
    check_time_machine
    check_filevault_recovery_key
    check_secure_keyboard_entry
    check_bluetooth_status
    check_sharing_services
    check_firmware_password
    check_secure_boot
    check_auto_login_items
    check_ntp_status
    check_sudo_config
    check_unsigned_kexts
    check_secure_empty_trash
    check_stealth_mode
    check_gatekeeper_quarantine
    check_cleartext_passwords
    check_insecure_https
    check_world_readable_files
    check_weak_ssh_config
    check_unencrypted_backups
    check_shell_history
    check_keychain_settings
    check_plist_passwords
    check_safari_settings
    check_log_files
    check_known_malware
    check_suspicious_connections
    check_stored_sessions
    check_browser_passwords
    check_ssh_keys
    check_cron_jobs
	check_safari_passwords
    check_firefox_passwords
	check_reverse_shell
    check_privilege_escalation
    check_unusual_processes
    check_network_connections
    check_hidden_files
    check_malware
    check_passwords_in_memory
    check_keychain_security

    print_and_log ""
    print_and_log "${GREEN}Security Assessment Complete${NC}"
    print_and_log "${YELLOW}Please review the results carefully and address any issues found.${NC}"
    print_and_log ""
    print_and_log "A detailed report has been saved to: $OUTPUT_FILE"

    # Remove color codes from the output file
    /usr/bin/sed -i '' 's/\x1b\[[0-9;]*m//g' "$OUTPUT_FILE"
    echo "A detailed report has been saved to: $OUTPUT_FILE"
}

# Run the main function
main
