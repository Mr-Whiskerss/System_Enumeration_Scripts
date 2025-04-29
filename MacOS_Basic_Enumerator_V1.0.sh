#!/bin/bash

# -----------------------------------------------------------------------------
# MacOS Basic Enumerator Script
# Purpose: Quickly gather common system info on macOS machines.
# Note: Not intended to replace MacPEAS. Inspired by HackTricks.
# Author: MrWhiskers
# Usage: Make executable and run with ./MacOS_Basic_Enumerator.sh
# No root required. Tested on M1 MacBook Air.
# -----------------------------------------------------------------------------

output_file="system_enumeration_report.txt"

# Function to run a command and append its output to the log
run_and_log() {
    echo "===== $1 =====" >> "$output_file"
    if command -v ${3:-true} >/dev/null 2>&1; then
        eval "$2" >> "$output_file" 2>&1
    else
        echo "[Command not found or unsupported on this system]" >> "$output_file"
    fi
    echo -e "\n" >> "$output_file"
}

# Clear previous output
> "$output_file"

echo "Starting enumeration on $(hostname) at $(date)" >> "$output_file"
echo "--------------------------------------------------" >> "$output_file"

# --- Basic System Info ---
run_and_log "Current Date" "date"
run_and_log "Calendar" "cal"
run_and_log "System Uptime" "uptime"
run_and_log "Logged-in Users" "w"
run_and_log "Current User" "whoami"
run_and_log "Finger Info" "finger \$(whoami)" "finger"
run_and_log "Kernel & OS Info" "uname -a"

# --- CPU & Memory ---
run_and_log "Processor Info" "sysctl -n machdep.cpu.brand_string"
run_and_log "Memory Statistics" "vm_stat"
run_and_log "Free Memory Summary" "top -l 1 | grep PhysMem"

# --- Disk & Filesystems ---
run_and_log "Disk Usage" "df -h"
run_and_log "Disk Utility List" "diskutil list"

# --- Services & Launch Items ---
run_and_log "Launchctl Services" "launchctl list"
run_and_log "AT Jobs (if available)" "at -l" "at"

# --- Kernel Info ---
run_and_log "All Kernel Parameters" "sysctl -a"

# --- Networking ---
run_and_log "ARP Table (en0)" "arp -i en0 -l -a" "arp"
run_and_log "Listening Network Ports" "lsof -i -P -n | grep LISTEN"
run_and_log "Mounted SMB Shares" "smbutil statshares -a" "smbutil"
run_and_log "All Network Services" "networksetup -listallnetworkservices"
run_and_log "All Hardware Ports" "networksetup -listallhardwareports"
run_and_log "Wi-Fi Info" "networksetup -getinfo Wi-Fi"
run_and_log "Wi-Fi Auto Proxy URL" "networksetup -getautoproxyurl Wi-Fi"
run_and_log "Wi-Fi Web Proxy" "networksetup -getwebproxy Wi-Fi"
run_and_log "Wi-Fi FTP Proxy" "networksetup -getftpproxy Wi-Fi"

# --- System Profiler Information ---
run_and_log "System Software Info" "system_profiler SPSoftwareDataType"
run_and_log "Printers" "system_profiler SPPrintersDataType"
run_and_log "Installed Applications" "system_profiler SPApplicationsDataType"
run_and_log "Installed Frameworks" "system_profiler SPFrameworksDataType"
run_and_log "Developer Tools" "system_profiler SPDeveloperToolsDataType"
run_and_log "Startup Items" "system_profiler SPStartupItemDataType"
run_and_log "Network Info" "system_profiler SPNetworkDataType"
run_and_log "Firewall Info" "system_profiler SPFirewallDataType"
run_and_log "Known Network Locations" "system_profiler SPNetworkLocationDataType"
run_and_log "Bluetooth Info" "system_profiler SPBluetoothDataType"
run_and_log "Ethernet Info" "system_profiler SPEthernetDataType"
run_and_log "USB Devices" "system_profiler SPUSBDataType"
run_and_log "Wi-Fi (Airport) Info" "system_profiler SPAirPortDataType"
run_and_log "System Profiler Help" "system_profiler --help"
run_and_log "Available System Profiler Data Types" "system_profiler -listDataTypes"

# --- File Discovery ---
run_and_log "Files Containing 'password'" "mdfind password"
run_and_log "Files Named Like 'password'" "find / -name '*password*' 2>/dev/null"

# --- Clipboard ---
run_and_log "Clipboard Contents" "pbpaste"

# --- Optional: Open Example Applications ---
# Uncomment the lines below if you want this behavior
# run_and_log "Open TextEdit" "open -a 'TextEdit' --hide"
# run_and_log "Open some.doc in TextEdit" "open some.doc -a 'TextEdit'"

# --- Prevent Sleep (runs in background) ---
run_and_log "Preventing Sleep (Caffeinate)" "caffeinate &"

# --- Completion ---
echo "System enumeration completed at $(date)." >> "$output_file"
echo "Output saved to $output_file"

