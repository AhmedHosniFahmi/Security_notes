- [Environment Enumeration](#environment-enumeration)
- [Services & Internals Enumeration](#services-&-internals-enumeration)
- [Search in the system](#search-in-the-system)
- [Network](#network)
---
### Environment Enumeration
``` bash
# what user are we running as  
whoami  
  
# Kernel version  
uname -a  
cat /proc/version  
  
# Sudo version  
sudo -V  
  
# can our user run anything with sudo (as another user as root)  
sudo -l  
  
# What groups does our user belong to?  
id  
  
# What is the server named?  
hostname  
  
#Existing Groups  
cat /etc/group  
  
# List members of group  
getent group <groupName>  
  
# operating system and version  
cat /etc/os-release  
  
# passwd and shadow files can be subjected to an offline password cracking attack  
cat /etc/shadow  
cat /etc/passwd  
  
# PATH variable for a target user is misconfigured we may be able to leverage it to escalate privileges.  
echo $PATH  
  
# find something sensitive in there such as a password  
env  
  
# What login shells exist  
cat /etc/shells  
  
# enumerate information about block devices on the system (hard disks, USB drives, optical drives, etc.)  
lsblk  
  
# CPU type/version  
lscpu  
  
# Mounted File Systems  
df -h  
  
# find any types of credentials in fstab for mounted drives by grepping for common words such as password, username, credential  
cat /etc/fstab  
  
# Unmounted File Systems  
cat /etc/fstab | grep -v "#" | column -t  
  
# can be used to find information about any printers attached to the system.  
#If there are active or queued print jobs can we gain access to some sort of sensitive information?  
lpstat   
  
# All Hidden Files  
find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null   
  
# All Hidden Directories  
find / -type d -name ".*" -ls 2>/dev/null  
  
# list all current dir  
ls -ahlR  
  
# Temporary Files  
# /var/tmp retained up to 30 days, used by programs to store data that must be kept between reboots temporarily.  
# /tmp automatically deleted after ten days and deleted immediately when the system is restarted.  
ls -l /tmp /var/tmp /dev/shm
```
---
### Services & Internals Enumeration
``` bash
# User's Last Login  
lastlog  
  
# Logged in users  
w  
  
# Who is currently on the system with us  
who  
finger  
finger <username>  
  
# History  
history  
  
# Cron  
ls -la /etc/cron.*/  
  
# (proc / procfs) is a filesystem in Linux that contains information about system processes, hardware, and other system information.  
find /proc -name cmdline -exec cat {} \; 2>/dev/null | tr " " "\n"  
  
# Installed Packages  
apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list  
  
# Sudo Version  
sudo -V  
  
# Binaries  
ls -l /bin /usr/bin/ /usr/sbin/  
  
# GTFObins exploitable binaries  
for i in $(curl -s https://gtfobins.github.io/ | html2text | cut -d" " -f1 |  
 sed '/^[[:space:]]*$/d');do if grep -q "$i" installed_pkgs.list;then echo "Check GTFO for: $i";fi;done  
  
# Use strace tool to track and analyze system calls and signal processing.  
strace ping -c1 10.129.112.20  
  
# Running Services by User  
ps aux | grep root
```
---
### Search in the system
``` bash
# Search for Writeable Directories  
find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null  
  
# Search for Writeable Files  
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null  
  
# search for specific names in files such as cred, passwords, users, secrets.  
find / -name *cred*  
  
# search for a specific word within a text file.  
grep -rn / -ie cred  
  
# Configuration Files  
find / -type f \( -name *.conf -o -name *.config \) -exec ls -l {} \; 2>/dev/null  
for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done  
find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null  
  
# Backup Files  
find / -iname "*.bak*" -type f 2>/dev/null  
  
# Credentials in Configuration Files  
for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done  
for i in $(find / -name *.conf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done  
  
# Finding History Files  
find / -type f \( -name *_hist -o -name *_history \) -exec ls -l {} \; 2>/dev/null  
  
# Databases  
for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done  
  
# Hunt database credentials  
grep -rn / -ie 'DB_USER\|DB_PASSWORD'  
  
# Notes  
find /home/* -type f -name "*.txt" -o ! -name "*.*"  
  
# Scripts  
for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done  
find / -type f -name "*.sh" 2>/dev/null | grep -v "src\|snap\|share"  
  
# find writable files or directories  
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null  
  
# find crontabs  
find /etc -type d -name '*cron*' -exec sh -c 'echo "Parent Directory: $1"; ls -lah "$1"' sh {} \;  
  
# ssh keys  
grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1"    ## private  
grep -rnw "ssh-rsa" /home/* 2>/dev/null | grep ":1"        ## public  
  
# Whenever finding SSH keys check the known_hosts file to find targets.  
# SSH Directory Content  
ls /home/<user>/.ssh
```
---
### Network
``` bash
# Network Interfaces  
ip a  
ifconfig  
  
# what other networks are available via which interface  
route  
netstat -rn  
  
# If the host is configured to use internal DNS we may be able to use this as a starting point to query the Active Directory environment.  
cat /etc/resolv.conf  
  
# Resolved Hosts  
cat /etc/hosts  
  
# check the arp table to see what other hosts the target has been communicating with.  
arp -a
```
---
