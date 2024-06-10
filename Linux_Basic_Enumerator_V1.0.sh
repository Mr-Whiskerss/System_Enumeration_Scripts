#Tool Purpose- To enumerate basic information from linux machines. This script is not designed to replace linpeas or linenum scripts but is designed to be droped onto a box aid within Linux build reviews during a build review assessment.
#Author - MrWhiskers 
#This script does not need root priv to run just make it excutable and run it with ./Linux_Basic_Enumerator.sh
#This Script attempts to enuemrate most common information nededed and includes multiple commands to run on different systems. 
#STILL IN BETA PLEASE RECOMMEND CHANGES.Reach out over twitter or linkedin.


#!/bin/bash

# Define the output file
OUTPUT="system_enumeration_report.txt"

# Create or clear the output file
: > "$OUTPUT"

echo "System Enumeration Report" | tee -a "$OUTPUT"
echo "=========================" | tee -a "$OUTPUT"
echo "" | tee -a "$OUTPUT"

# Operating System Information
echo "Operating System Information" | tee -a "$OUTPUT"
echo "----------------------------" | tee -a "$OUTPUT"
echo "Distribution Information:" | tee -a "$OUTPUT"
cat /etc/issue | tee -a "$OUTPUT"
cat /etc/*-release | tee -a "$OUTPUT"
cat /etc/lsb-release | tee -a "$OUTPUT"
cat /etc/redhat-release | tee -a "$OUTPUT"
echo "" | tee -a "$OUTPUT"

echo "Kernel Version:" | tee -a "$OUTPUT"
cat /proc/version | tee -a "$OUTPUT"
uname -a | tee -a "$OUTPUT"
uname -mrs | tee -a "$OUTPUT"
rpm -q kernel 2>/dev/null | tee -a "$OUTPUT"
dmesg | grep Linux | tee -a "$OUTPUT"
ls /boot | grep vmlinuz- | tee -a "$OUTPUT"
echo "" | tee -a "$OUTPUT"

# Environmental Variables
echo "Environmental Variables" | tee -a "$OUTPUT"
echo "-----------------------" | tee -a "$OUTPUT"
cat /etc/profile | tee -a "$OUTPUT"
cat /etc/bashrc | tee -a "$OUTPUT"
cat ~/.bash_profile 2>/dev/null | tee -a "$OUTPUT"
cat ~/.bashrc 2>/dev/null | tee -a "$OUTPUT"
cat ~/.bash_logout 2>/dev/null | tee -a "$OUTPUT"
env | tee -a "$OUTPUT"
set | tee -a "$OUTPUT"
echo "" | tee -a "$OUTPUT"

# Printer Information
echo "Printer Information" | tee -a "$OUTPUT"
echo "-------------------" | tee -a "$OUTPUT"
lpstat -a 2>/dev/null | tee -a "$OUTPUT"
echo "" | tee -a "$OUTPUT"

# Running Services
echo "Running Services" | tee -a "$OUTPUT"
echo "----------------" | tee -a "$OUTPUT"
ps aux | tee -a "$OUTPUT"
ps -ef | tee -a "$OUTPUT"
top -b -n 1 | tee -a "$OUTPUT"
cat /etc/services | tee -a "$OUTPUT"
echo "" | tee -a "$OUTPUT"

echo "Services Running as Root" | tee -a "$OUTPUT"
ps aux | grep root | tee -a "$OUTPUT"
ps -ef | grep root | tee -a "$OUTPUT"
echo "" | tee -a "$OUTPUT"

# Installed Applications
echo "Installed Applications" | tee -a "$OUTPUT"
echo "----------------------" | tee -a "$OUTPUT"
ls -alh /usr/bin/ | tee -a "$OUTPUT"
ls -alh /sbin/ | tee -a "$OUTPUT"
dpkg -l 2>/dev/null | tee -a "$OUTPUT"
rpm -qa 2>/dev/null | tee -a "$OUTPUT"
ls -alh /var/cache/apt/archives 2>/dev/null | tee -a "$OUTPUT"
ls -alh /var/cache/yum/ 2>/dev/null | tee -a "$OUTPUT"
echo "" | tee -a "$OUTPUT"

# Service Configuration Files
echo "Service Configuration Files" | tee -a "$OUTPUT"
echo "---------------------------" | tee -a "$OUTPUT"
cat /etc/syslog.conf 2>/dev/null | tee -a "$OUTPUT"
cat /etc/chttp.conf 2>/dev/null | tee -a "$OUTPUT"
cat /etc/lighttpd/lighttpd.conf 2>/dev/null | tee -a "$OUTPUT"
cat /etc/cups/cupsd.conf 2>/dev/null | tee -a "$OUTPUT"
cat /etc/inetd.conf 2>/dev/null | tee -a "$OUTPUT"
cat /etc/apache2/apache2.conf 2>/dev/null | tee -a "$OUTPUT"
cat /etc/mysql/my.cnf 2>/dev/null | tee -a "$OUTPUT"
cat /etc/httpd/conf/httpd.conf 2>/dev/null | tee -a "$OUTPUT"
cat /opt/lampp/etc/httpd.conf 2>/dev/null | tee -a "$OUTPUT"
ls -aRl /etc/ | awk '$1 ~ /^.*r.*/' | tee -a "$OUTPUT"
echo "" | tee -a "$OUTPUT"

# Scheduled Jobs
echo "Scheduled Jobs" | tee -a "$OUTPUT"
echo "--------------" | tee -a "$OUTPUT"
crontab -l 2>/dev/null | tee -a "$OUTPUT"
ls -alh /var/spool/cron | tee -a "$OUTPUT"
ls -al /etc/ | grep cron | tee -a "$OUTPUT"
ls -al /etc/cron* | tee -a "$OUTPUT"
cat /etc/cron* 2>/dev/null | tee -a "$OUTPUT"
cat /etc/at.allow 2>/dev/null | tee -a "$OUTPUT"
cat /etc/at.deny 2>/dev/null | tee -a "$OUTPUT"
cat /etc/cron.allow 2>/dev/null | tee -a "$OUTPUT"
cat /etc/cron.deny 2>/dev/null | tee -a "$OUTPUT"
cat /etc/crontab 2>/dev/null | tee -a "$OUTPUT"
cat /etc/anacrontab 2>/dev/null | tee -a "$OUTPUT"
cat /var/spool/cron/crontabs/root 2>/dev/null | tee -a "$OUTPUT"
echo "" | tee -a "$OUTPUT"

# Plain Text Passwords Search
echo "Plain Text Passwords Search" | tee -a "$OUTPUT"
echo "---------------------------" | tee -a "$OUTPUT"
grep -i user /etc/* 2>/dev/null | tee -a "$OUTPUT"
grep -i pass /etc/* 2>/dev/null | tee -a "$OUTPUT"
grep -C 5 "password" /etc/* 2>/dev/null | tee -a "$OUTPUT"
find . -name "*.php" -print0 | xargs -0 grep -i -n "var $password" 2>/dev/null | tee -a "$OUTPUT"
echo "" | tee -a "$OUTPUT"

# Network Configuration
echo "Network Configuration" | tee -a "$OUTPUT"
echo "---------------------" | tee -a "$OUTPUT"
echo "Network Interfaces:" | tee -a "$OUTPUT"
/sbin/ifconfig -a | tee -a "$OUTPUT"
cat /etc/network/interfaces 2>/dev/null | tee -a "$OUTPUT"
cat /etc/sysconfig/network 2>/dev/null | tee -a "$OUTPUT"
echo "" | tee -a "$OUTPUT"

echo "Network Settings:" | tee -a "$OUTPUT"
cat /etc/resolvectl | tee -a "$OUTPUT"
cat /etc/sysconfig/network 2>/dev/null | tee -a "$OUTPUT"
cat /etc/networks | tee -a "$OUTPUT"
iptables -L 2>/dev/null | tee -a "$OUTPUT"
hostname | tee -a "$OUTPUT"
dnsdomainname | tee -a "$OUTPUT"
echo "" | tee -a "$OUTPUT"

echo "Network Connections:" | tee -a "$OUTPUT"
lsof -i | tee -a "$OUTPUT"
lsof -i :80 | tee -a "$OUTPUT"
grep 80 /etc/services | tee -a "$OUTPUT"
netstat -antup | tee -a "$OUTPUT"
netstat -antpx | tee -a "$OUTPUT"
netstat -tulpn | tee -a "$OUTPUT"
chkconfig --list 2>/dev/null | tee -a "$OUTPUT"
chkconfig --list | grep 3:on 2>/dev/null | tee -a "$OUTPUT"
last | tee -a "$OUTPUT"
w | tee -a "$OUTPUT"
echo "" | tee -a "$OUTPUT"

echo "Cached IP/MAC Addresses:" | tee -a "$OUTPUT"
arp -e | tee -a "$OUTPUT"
route | tee -a "$OUTPUT"
/sbin/route -nee | tee -a "$OUTPUT"
echo "" | tee -a "$OUTPUT"

echo "System Enumeration Report End" | tee -a "$OUTPUT"
