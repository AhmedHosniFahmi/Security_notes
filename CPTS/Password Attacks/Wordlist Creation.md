### Content
- [Create Username Wordlists](#create-username-wordlists)
- [Mutate Wordlists](#mutate-wordlists)
- [Credentials Stuffing](#credentials-stuffing)
- [Types of Brute Forcing](#types-of-brute-forcing)
---
# Create Username Wordlists
- [Username Anarchy](https://github.com/urbanadventurer/username-anarchy.git)
	``` bash
	./username-anarchy john doe > john_doe_usernames.txt
	```
- [CUPP](https://github.com/Mebus/cupp)
	```
	cupp -i
	```
- [CeWL](https://github.com/digininja/CeWL)
	``` bash
	cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist
	```
---
# Mutate Wordlists
We can use a very powerful tool called [Hashcat](https://hashcat.net/hashcat/) to combine lists of potential names and labels with specific mutation rules to create custom wordlists.
- Hashcat uses a specific syntax for defining characters and words and how they can be modified. The complete list of this syntax can be found in the official [documentation](https://hashcat.net/wiki/doku.php?id=rule_based_attack) of Hashcat. ex :
	- `:` Don nothing.
	- `l` Lowercase all letters.
	- `u` Uppercase all letters.
	- `c` Capitalize the first letter and lowercase others.
	- `sXY` Replace all instances of `X` with `Y`.
	- `$!` Add exclamation character at the end.
- Each rule is written on a new line which determines how the word should be mutated. custom rules file example:
	``` txt
	:
	c
	so0
	c so0
	sa@
	c sa@
	c sa@ so0
	$!
	$! c
	$! so0
	$! sa@
	$! c so0
	$! c sa@
	$! so0 sa@
	$! c so0 sa@
	```
- Generating Rule-based Wordlist
	``` bash
	$ hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
	$ cat mut_password.list
	```
- `Hashcat` and `John` come with pre-built rule lists that we can use for our password generating and cracking purposes.
	```bash
	$ ls /usr/share/hashcat/rules/
	
	best64.rule                  specific.rule
	combinator.rule              T0XlC-insert_00-99_1950-2050_toprules_0_F.rule
	d3ad0ne.rule                 T0XlC-insert_space_and_special_0_F.rule
	dive.rule                    T0XlC-insert_top_100_passwords_1_G.rule
	generated2.rule              T0XlC.rule
	generated.rule               T0XlCv1.rule
	hybrid                       toggles1.rule
	Incisive-leetspeak.rule      toggles2.rule
	InsidePro-HashManager.rule   toggles3.rule
	InsidePro-PasswordsPro.rule  toggles4.rule
	leetspeak.rule               toggles5.rule
	oscommerce.rule              unix-ninja-leetspeak.rule
	rockyou-30000.rule
	```

---
### Credentials Stuffing
Attacking services with the default or obtained credentials is called [Credential Stuffing](https://owasp.org/www-community/attacks/Credential_stuffing).
- There are various databases that keep a running list of known default credentials. One of them is the [DefaultCreds-Cheat-Sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet).
	``` bash
	$ pipx install defaultcreds-cheat-sheet
	$ creds search tomcat
	$ creads search tomcat export
	```
- [A list for default credentials for routers](https://www.softwaretestinghelp.com/default-router-username-and-password-list/)

---
### Types of Brute Forcing

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
