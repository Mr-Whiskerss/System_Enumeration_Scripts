#Tool Purpose- To enumerate basic information from MacOS machines. This script is not designed to replace MacPeas scripts but is designed to be droped onto a box aid within MacOS build reviews during a build review assessment. Commands taken from HackTricks thank you!
#Author - MrWhiskers 
#This script does not need root priv to run just make it excutable and run it with ./MacOS_Basic_Enumerator.sh
#This Script attempts to enuemrate most common information nededed and includes multiple commands to run on different systems. This Script has only been tested on my M1 air.
#STILL IN BETA PLEASE RECOMMEND CHANGES.Reach out over twitter or linkedin.

#!/bin/bash

# Output file
output_file="system_enumeration_report.txt"

# Function to run a command and append its output to the file with a heading
run_and_log() {
    echo "===== $1 =====" >> "$output_file"
    eval "$2" >> "$output_file" 2>&1
    echo -e "\n" >> "$output_file"
}

# Clear the output file
> "$output_file"

# System info commands
# Get the current date and time
run_and_log "Date" "date"

# Display the current month's calendar
run_and_log "Calendar" "cal"

# Show system uptime and load average
run_and_log "Uptime" "uptime"

# List logged-in users and their activities
run_and_log "Users" "w"

# Display the current username
run_and_log "Current User" "whoami"

# Provide information about the current user
run_and_log "Finger Information for Current User" "finger $(whoami)"

# Show system information including kernel version
run_and_log "System Information" "uname -a"

# Display detailed information about the processor (Note: '/proc/cpuinfo' may not exist on MacOS)
run_and_log "Processor Info" "sysctl -n machdep.cpu.brand_string"

# Display information about system memory (Note: '/proc/meminfo' may not exist on MacOS)
run_and_log "Memory Info" "vm_stat"

# Display the amount of free and used memory in the system
run_and_log "Free Memory" "top -l 1 | grep PhysMem"

# Display disk usage for all mounted filesystems
run_and_log "Disk Usage" "df -h"

# Service-related commands
# List all services managed by launchctl
run_and_log "Launchctl List Services" "launchctl list"

# List scheduled 'at' jobs for the current user (Note: 'at' might not be available or used differently on MacOS)
run_and_log "AT Tasks" "at -l"

# Display all kernel parameters
run_and_log "Kernel Configuration" "sysctl -a"

# List all connected disks and partitions
run_and_log "Disk Utility List" "diskutil list"

# Monitor network usage by processes (This command will run briefly due to the '-l 1' option)
run_and_log "Network Top Processes" "nettop -n -x -l 1"

# System profiler commands
# Show detailed software information
run_and_log "Software Info" "system_profiler SPSoftwareDataType"

# Display information about installed printers
run_and_log "Printer Info" "system_profiler SPPrintersDataType"

# List all installed applications
run_and_log "Installed Applications" "system_profiler SPApplicationsDataType"

# Show information about installed frameworks
run_and_log "Installed Frameworks" "system_profiler SPFrameworksDataType"

# Provide details about installed developer tools
run_and_log "Developer Tools Info" "system_profiler SPDeveloperToolsDataType"

# List startup items
run_and_log "Startup Items" "system_profiler SPStartupItemDataType"

# Display network capabilities
run_and_log "Network Capabilities" "system_profiler SPNetworkDataType"

# Show firewall status
run_and_log "Firewall Status" "system_profiler SPFirewallDataType"

# List known network locations
run_and_log "Known Network Locations" "system_profiler SPNetworkLocationDataType"

# Display Bluetooth information
run_and_log "Bluetooth Info" "system_profiler SPBluetoothDataType"

# Show Ethernet information
run_and_log "Ethernet Info" "system_profiler SPEthernetDataType"

# Display USB device information
run_and_log "USB Info" "system_profiler SPUSBDataType"

# Provide details about Airport (Wi-Fi) information
run_and_log "Airport Info" "system_profiler SPAirPortDataType"

# File searches
# Find files containing the word 'password'
run_and_log "Files Containing 'password'" "mdfind password"

# Find files with 'password' in the name
run_and_log "Files Named 'password'" "find / -name '*password*'"

# Open applications (examples, you can customize the application name)
# Open TextEdit application in a hidden state
run_and_log "Open TextEdit" "open -a 'TextEdit' --hide"

# Open a document named 'some.doc' in TextEdit
run_and_log "Open some.doc in TextEdit" "open some.doc -a 'TextEdit'"

# Prevent the system from sleeping (background process)
run_and_log "Caffeinate (Prevent Sleep)" "caffeinate &"

# Clipboard info
# Display the contents of the clipboard
run_and_log "Clipboard Contents" "pbpaste"

# Additional system profiler commands
# Display help information for the system_profiler command
run_and_log "System Profiler Help" "system_profiler --help"

# List all available data types for system_profiler
run_and_log "List Data Types for System Profiler" "system_profiler -listDataTypes"

# Show software and network information using system_profiler
run_and_log "Specific System Profiler Data Types" "system_profiler SPSoftwareDataType SPNetworkDataType"

# Network-related commands
# Display the ARP table for interface en0
run_and_log "ARP Table" "arp -i en0 -l -a"

# List all open network sockets and their status
run_and_log "Listening Ports" "lsof -i -P -n | grep LISTEN"

# View SMB shares mounted to the hard drive
run_and_log "SMB Shares" "smbutil statshares -a"

# List all network services available on the system
run_and_log "List All Network Services" "networksetup -listallnetworkservices"

# List all hardware ports and their associated devices
run_and_log "List All Hardware Ports" "networksetup -listallhardwareports"

# Get information about the Wi-Fi network
run_and_log "Wi-Fi Info" "networksetup -getinfo Wi-Fi"

# Get the automatic proxy URL for Wi-Fi
run_and_log "Wi-Fi Proxy URL" "networksetup -getautoproxyurl Wi-Fi"

# Get the web proxy configuration for Wi-Fi
run_and_log "Wi-Fi Web Proxy" "networksetup -getwebproxy Wi-Fi"

# Get the FTP proxy configuration for Wi-Fi
run_and_log "Wi-Fi FTP Proxy" "networksetup -getftpproxy Wi-Fi"

echo "System information has been logged to $output_file"
