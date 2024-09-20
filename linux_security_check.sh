#!/bin/bash

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Output file
OUTPUT_FILE="$(dirname "$0")/ubuntu_security_assessment_$(date +%Y%m%d_%H%M%S).txt"

# Utility functions
print_and_log() {
    echo -e "$1"
    echo -e "$1" >> "$OUTPUT_FILE"
}

print_header() {
    print_and_log ""
    print_and_log "${CYAN}## $1${NC}"
    print_and_log "-------------------"
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Print banner
print_banner() {
    print_and_log "${BLUE}=================================================${NC}"
    print_and_log "${BLUE} Northernlight Re IT Assessment${NC}"
    print_and_log "${BLUE}=================================================${NC}"
    print_and_log ""
    print_and_log "${YELLOW}Ubuntu Security Assessment${NC}"
    print_and_log "${YELLOW}=========================${NC}"
    print_and_log ""
    print_and_log "${CYAN}Date: $(date)${NC}"
    print_and_log "${CYAN}Hostname: $(hostname)${NC}"
    print_and_log "${CYAN}Ubuntu Version: $(lsb_release -d | cut -f2)${NC}"
    print_and_log ""
}

# Previous security check functions
check_firewall() {
    print_header "Firewall Status"
    if command_exists ufw && ufw status | grep -q "active"; then
        print_and_log "${GREEN}✅ Firewall (ufw) is enabled${NC}"
    else
        print_and_log "${RED}❌ Firewall (ufw) is disabled or not installed${NC}"
    fi
}

check_updates() {
    print_header "System Updates"
    if [ -f /var/run/reboot-required ]; then
        print_and_log "${YELLOW}⚠️ System restart required${NC}"
    fi
    updates=$(apt list --upgradable 2>/dev/null | grep -c "upgradable")
    if [ "$updates" -gt 0 ]; then
        print_and_log "${YELLOW}⚠️ $updates updates available${NC}"
    else
        print_and_log "${GREEN}✅ System is up to date${NC}"
    fi
}

check_ssh() {
    print_header "SSH Configuration"
    if [ -f /etc/ssh/sshd_config ]; then
        if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config; then
            print_and_log "${GREEN}✅ Root login via SSH is disabled${NC}"
        else
            print_and_log "${RED}❌ Root login via SSH is not explicitly disabled${NC}"
        fi
    else
        print_and_log "${YELLOW}⚠️ SSH server is not installed${NC}"
    fi
}

check_password_policy() {
    print_header "Password Policy"
    if [ -f /etc/pam.d/common-password ]; then
        if grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
            print_and_log "${GREEN}✅ Password quality requirements are set${NC}"
        else
            print_and_log "${YELLOW}⚠️ No password quality requirements found${NC}"
        fi
    else
        print_and_log "${RED}❌ Password policy file not found${NC}"
    fi
}

check_disk_encryption() {
    print_header "Disk Encryption"
    if command_exists cryptsetup; then
        encrypted_devices=$(lsblk -f | grep -c "crypto_LUKS")
        if [ "$encrypted_devices" -gt 0 ]; then
            print_and_log "${GREEN}✅ $encrypted_devices encrypted devices found${NC}"
        else
            print_and_log "${YELLOW}⚠️ No encrypted devices found${NC}"
        fi
    else
        print_and_log "${RED}❌ Disk encryption tools not installed${NC}"
    fi
}

check_automatic_login() {
    print_header "Automatic Login"
    if [ -f /etc/gdm3/custom.conf ]; then
        if grep -q "AutomaticLoginEnable=true" /etc/gdm3/custom.conf; then
            print_and_log "${RED}❌ Automatic login is enabled${NC}"
        else
            print_and_log "${GREEN}✅ Automatic login is disabled${NC}"
        fi
    else
        print_and_log "${YELLOW}⚠️ GDM3 configuration file not found${NC}"
    fi
}

check_guest_account() {
    print_header "Guest Account"
    if [ -f /etc/lightdm/lightdm.conf ]; then
        if grep -q "allow-guest=false" /etc/lightdm/lightdm.conf; then
            print_and_log "${GREEN}✅ Guest account is disabled${NC}"
        else
            print_and_log "${YELLOW}⚠️ Guest account may be enabled${NC}"
        fi
    else
        print_and_log "${YELLOW}⚠️ LightDM configuration file not found${NC}"
    fi
}

check_apparmor() {
    print_header "AppArmor Status"
    if command_exists apparmor_status; then
        if apparmor_status | grep -q "apparmor module is loaded."; then
            print_and_log "${GREEN}✅ AppArmor is enabled and loaded${NC}"
        else
            print_and_log "${RED}❌ AppArmor is not enabled${NC}"
        fi
    else
        print_and_log "${RED}❌ AppArmor is not installed${NC}"
    fi
}

check_auditd() {
    print_header "Audit Daemon"
    if command_exists auditd; then
        if systemctl is-active --quiet auditd; then
            print_and_log "${GREEN}✅ Audit daemon is active${NC}"
        else
            print_and_log "${RED}❌ Audit daemon is installed but not active${NC}"
        fi
    else
        print_and_log "${YELLOW}⚠️ Audit daemon is not installed${NC}"
    fi
}

check_usb_guard() {
    print_header "USBGuard"
    if command_exists usbguard; then
        if systemctl is-active --quiet usbguard; then
            print_and_log "${GREEN}✅ USBGuard is active${NC}"
        else
            print_and_log "${YELLOW}⚠️ USBGuard is installed but not active${NC}"
        fi
    else
        print_and_log "${YELLOW}⚠️ USBGuard is not installed${NC}"
    fi
}

check_core_dumps() {
    print_header "Core Dumps"
    if [ -f /etc/security/limits.conf ]; then
        if grep -q "* hard core 0" /etc/security/limits.conf; then
            print_and_log "${GREEN}✅ Core dumps are disabled${NC}"
        else
            print_and_log "${YELLOW}⚠️ Core dumps may be enabled${NC}"
        fi
    else
        print_and_log "${RED}❌ Security limits configuration file not found${NC}"
    fi
}

# Additional checks from previous update
check_sudo_nopasswd() {
    print_header "Sudo NOPASSWD Check"
    if sudo -l | grep -q "(ALL) NOPASSWD:"; then
        print_and_log "${RED}❌ Sudo NOPASSWD found, privilege escalation risk${NC}"
    else
        print_and_log "${GREEN}✅ No Sudo NOPASSWD entries found${NC}"
    fi
}

check_world_writable_files() {
    print_header "World-Writable Files"
    ww_files=$(find / -xdev -type f -perm -0002 2>/dev/null)
    if [ -n "$ww_files" ]; then
        print_and_log "${RED}❌ World-writable files found:${NC}"
        print_and_log "$ww_files"
    else
        print_and_log "${GREEN}✅ No world-writable files found${NC}"
    fi
}

check_suid_files() {
    print_header "SUID Files"
    suid_files=$(find / -xdev -type f -perm /4000 2>/dev/null)
    if [ -n "$suid_files" ]; then
        print_and_log "${YELLOW}⚠️ SUID files found:${NC}"
        print_and_log "$suid_files"
    else
        print_and_log "${GREEN}✅ No SUID files found${NC}"
    fi
}

check_bash_history_for_passwords() {
    print_header "Bash History for Passwords"
    if grep -q "password" ~/.bash_history; then
        print_and_log "${RED}❌ Passwords found in bash history${NC}"
    else
        print_and_log "${GREEN}✅ No passwords found in bash history${NC}"
    fi
}

check_root_user_ssh_keys() {
    print_header "Root User SSH Keys"
    if [ -f /root/.ssh/authorized_keys ]; then
        print_and_log "${RED}❌ Root user has SSH keys enabled${NC}"
    else
        print_and_log "${GREEN}✅ No SSH keys found for root user${NC}"
    fi
}

check_old_kernels() {
    print_header "Old Kernel Versions"
    old_kernels=$(dpkg -l 'linux-image-*' | grep '^ii' | grep -v "$(uname -r)" | awk '{ print $2 }')
    if [ -n "$old_kernels" ]; then
        print_and_log "${YELLOW}⚠️ Old kernels found:${NC}"
        print_and_log "$old_kernels"
    else
        print_and_log "${GREEN}✅ No old kernels found${NC}"
    fi
}

check_cron_jobs() {
    print_header "Cron Jobs"
    cron_jobs=$(crontab -l 2>/dev/null)
    if [ -n "$cron_jobs" ]; then
        print_and_log "${YELLOW}⚠️ Cron jobs found:${NC}"
        print_and_log "$cron_jobs"
    else
        print_and_log "${GREEN}✅ No cron jobs configured for the current user${NC}"
    fi
}

check_duplicate_uids() {
    print_header "Duplicate User IDs"
    dup_uids=$(awk -F: '{print $3}' /etc/passwd | sort | uniq -d)
    if [ -n "$dup_uids" ]; then
        print_and_log "${RED}❌ Duplicate UIDs found:${NC}"
        print_and_log "$dup_uids"
    else
        print_and_log "${GREEN}✅ No duplicate UIDs found${NC}"
    fi
}

check_duplicate_gids() {
    print_header "Duplicate Group IDs"
    dup_gids=$(awk -F: '{print $3}' /etc/group | sort | uniq -d)
    if [ -n "$dup_gids" ]; then
        print_and_log "${RED}❌ Duplicate GIDs found:${NC}"
        print_and_log "$dup_gids"
    else
        print_and_log "${GREEN}✅ No duplicate GIDs found${NC}"
    fi
}

check_unowned_files() {
    print_header "Unowned Files"
    unowned_files=$(find / -nouser -o -nogroup 2>/dev/null)
    if [ -n "$unowned_files" ]; then
        print_and_log "${YELLOW}⚠️ Unowned files found:${NC}"
        print_and_log "$unowned_files"
    else
        print_and_log "${GREEN}✅ No unowned files found${NC}"
    fi
}

# Main function
main() {
    print_banner

    # Run all the checks
    check_firewall
    check_updates
    check_ssh
    check_password_policy
    check_disk_encryption
    check_automatic_login
    check_guest_account
    check_apparmor
    check_auditd
    check_usb_guard
    check_core_dumps

    # New checks from previous script
    check_sudo_nopasswd
    check_world_writable_files
    check_suid_files
    check_bash_history_for_passwords
    check_root_user_ssh_keys
    check_old_kernels
    check_cron_jobs
    check_duplicate_uids
    check_duplicate_gids
    check_unowned_files

    print_and_log ""
    print_and_log "${GREEN}Security Assessment Complete${NC}"
    print_and_log "${YELLOW}Please review the results carefully and address any issues found.${NC}"
    print_and_log ""
    print_and_log "A detailed report has been saved to: $OUTPUT_FILE"

    # Remove color codes from the output file
    sed -i 's/\x1b\[[0-9;]*m//g' "$OUTPUT_FILE"

    echo "A detailed report has been saved to: $OUTPUT_FILE"
}

# Run the main function
main
