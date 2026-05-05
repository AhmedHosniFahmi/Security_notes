### Content

- [Directory fuzzing](#directory-fuzzing)
- [File fuzzing](#file-fuzzing)
- [Files extension fuzzing](#files-extension-fuzzing)
- [Recursive fuzzing](#recursive-fuzzing)
- [Sub-domains fuzzing](#sub-domains-fuzzing)
- [Virtual host fuzzing](#virtual-host-fuzzing)
- [Parameters fuzzing](#parameters-fuzzing)
	- GET Parameters
	- POST Parameters
- [API fuzzing](#api-fuzzing)

---

> [!Note]
> To validate your findings you can use something like `curl -I http://IP:PORT/password.txt` to see:
> - `Content-Type:` header containing the data type we expect to get, ex:
> 	- `text/plain` for text, `application/sql` for DB dump, `application/zip` for compressed file.
> - `Content-Length:` A value greater than zero suggests a file with actual content.
> 
> Add cookie to ffuf using `-b "PHPSESSID=39b54j201u3rhu4tab1pvdb4pv"` -> `NAME1=VALUE1; NAME2=VALUE2`

---
#### Directory fuzzing

``` bash
$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ/
```

---
#### File fuzzing

``` bash
$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/common.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ -e .html,.js,.bak,.db,.php,.txt
```

---
#### Files extension fuzzing

``` bash
# if the wordlist has (.) prefixed to each payload we will not user (index.FUZZ)   
$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://SERVER_IP:PORT/blog/indexFUZZ
```

---
#### Recursive fuzzing

``` bash
# ffuf
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://IP:PORT/FUZZ -recursion -recursion-depth 2 -e .html,.php,.txt -ic

# feroxbuster has depth 4 (-d 4) by default
$ feroxbuster --url http://IP:PORT/ --wordlist /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php html js -t 250
```

---
#### Sub-domains fuzzing

``` bash
# add the IP to /etc/hosts  
$ ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://FUZZ.academy.htb/  -t 200 -v

# Match HTTP status codes, or "all" for everything. (default: 200-299,301,302,307,401,403,405,500)
$ ffuf  -v -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://FUZZ.thetoppers.htb/  --mc all

$ gobuster dns --do inlanefreight.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

---
#### Virtual host fuzzing

``` bash
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -u 'http://inlanefreight.htb:44027' -H 'Host: FUZZ.inlanefreight.htb'

$ gobuster vhost -u http://inlanefreight.htb:44027 -w /usr/share/seclists/Discovery/Web-Content/common.txt  --append-domain -t 200
```

---
#### Parameters fuzzing

- GET

``` bash
$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx
```

- POST

The data in the post body request is encoded into specific format, it can be in:

- `application/x-www-form-urlencoded` which encodes the data as key-value pairs separated by ampersands (`&`), similar to GET parameters.
- `multipart/form-data` which used when submitting files along with other data. It divides the request body into multiple parts, each containing a specific piece of data or a file.

``` bash
# In PHP, "POST" data "content-type" can only accept "application/x-www-form-urlencoded"
$ ffuf -u http://IP:PORT/post.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "y=FUZZ" -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200 -v

$ for i in $(seq 1 1000); do echo $i >> ids.txt; done  
$ ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded'
```

---
#### API fuzzing

There are 3 primary types of API fuzzing

1. `Parameter Fuzzing`: systematically testing different values for API parameters, headers and request bodies.
2. `Data Format Fuzzing`: Targeting formats like JSON or XML by manipulating the structure, content, or encoding of the data. (parsing errors, buffer overflows, or improper handling of special characters)
3. `Sequence Fuzzing`: APIs often involve multiple interconnected endpoints, where the order and timing of requests are crucial. Sequence fuzzing examines how an API responds to sequences of requests, uncovering vulnerabilities like race conditions, insecure direct object references (IDOR), or authorization bypasses.

```bash
$ git clone https://github.com/PandaSt0rm/webfuzz_api.git
$ cd webfuzz_api
$ pip3 install -r requirements.txt

$ python3 api_fuzzer.py http://IP:PORT


[SNIP]

Fuzzing completed.
Total requests: 4730
Failed requests: 0
Retries: 0
Status code counts:
404: 4727
200: 2
405: 1
Found valid endpoints:
- http://localhost:8000/cz...
- http://localhost:8000/docs
Unusual status codes:
405: http://localhost:8000/items
```
