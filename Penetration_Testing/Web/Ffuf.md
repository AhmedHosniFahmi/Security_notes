- [Directory fuzzing](#directory-fuzzing)
- [Files extension fuzzing](#files-extension-fuzzing)
- [Page fuzzing](#page-fuzzing)
- [Recursive fuzzing](#recursive-fuzzing)
- [Sub-domains fuzzing](#sub-domains-fuzzing)
- [Virtual host fuzzing](#virtual-host-fuzzing)
- [Parameters fuzzing](#parameters-fuzzing)
	- GET Parameters
	- POST Parameters
- [Value fuzzing](#value-fuzzing)
##### Directory fuzzing
``` bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ
```
##### Files extension fuzzing
``` bash
# if the wordlist has (.) prefixed to each payload we will not user (index.FUZZ)   
ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://SERVER_IP:PORT/blog/indexFUZZ
```
##### Page fuzzing
``` bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php
```
##### Recursive fuzzing
``` bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v -ic
```
##### Sub-domains fuzzing
``` bash
# add the IP to /etc/hosts  
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://FUZZ.academy.htb/ -fs 900 -t 200 -v

# 
ffuf  -v -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://FUZZ.thetoppers.htb/  --mc all
```
##### Virtual host fuzzing
``` bash
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb'
```
##### Parameters fuzzing
- GET
	``` bash
	ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx
	```
- POST
	``` bash
	# In PHP, "POST" data "content-type" can only accept "application/x-www-form-urlencoded"
	ffuf -w PATH/TO/WORDLIST:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded'
	```
##### Value fuzzing
``` bash
$ for i in $(seq 1 1000); do echo $i >> ids.txt; done  
$ ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded'
```