### Content
- [Cracking modes](#cracking-modes)
- [Mutate Wordlists](#mutate-wordlists)

> [!Note]
> 
> - `hashcat -a [attackMode] -m [hashMode] <hashe string or file> [wordlist, rule,...]`
> - Rules can be used to perform specific modifications to passwords to generate even more guesses.
> - Rule files that come with hashcat are typically found under `/usr/share/hashcat/rules`
> 
>##### Identifying hash formats:
> - The hashcat website hosts a comprehensive list of [example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
> - Use a tool like [hashID](https://github.com/psypanda/hashID)
>   
> 	`hashid -m '$6$ues25dIanlctrWxg$......'`

---
## Cracking modes

[Dictionary attack](https://hashcat.net/wiki/doku.php?id=dictionary_attack) (`-a 0`)

```bash
$ hashcat -a 0 -m 0 <hash> /usr/share/wordlists/rockyou.txt
```

[Mask attack](https://hashcat.net/wiki/doku.php?id=mask_attack) (`-a 3`)

- It is a type of brute-force attack in which the keyspace is explicitly defined by the user.
- For example, if we know that a password is eight characters long, rather than attempting every possible combination.
- A mask is defined by combining a sequence of symbols, each representing a built-in or custom character set.
  
Hashcat includes several built-in character sets:

| Symbol | Charset                             |
| ------ | ----------------------------------- |
| ?l     | abcdefghijklmnopqrstuvwxyz          |
| ?u     | ABCDEFGHIJKLMNOPQRSTUVWXYZ          |
| ?d     | 0123456789                          |
| ?h     | 0123456789abcdef                    |
| ?H     | 0123456789ABCDEF                    |
| ?s     | «space»!"#$%&'()*+,-./:;<=>?@[]^_`{ |
| ?a     | ?l?u?d?s                            |
| ?b     | 0x00 - 0xff                         |

> Custom charsets can be defined with the `-1`, `-2`, `-3`, and `-4` arguments, then referred to with `?1`, `?2`, `?3`, and `?4`.

```bash
# Passwords start with an uppercase letter, continue with four lowercase letters, a digit, and then a symbol.
$ hashcat -a 3 -m 0 <hash> '?u?l?l?l?l?d?s'
```

---
## Mutate Wordlists

Hashcat uses a specific syntax for defining characters and words and how they can be modified. The complete list of this syntax can be found in the official [documentation](https://hashcat.net/wiki/doku.php?id=rule_based_attack) of Hashcat. ex :

| **Function** | **Description**                                  |
| ------------ | ------------------------------------------------ |
| `:`          | Do nothing                                       |
| `l`          | Lowercase all letters                            |
| `u`          | Uppercase all letters                            |
| `c`          | Capitalize the first letter and lowercase others |
| `sXY`        | Replace all instances of X with Y                |
| `$!`         | Add the exclamation character at the end         |

example of custom rules:
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

We can use the following command to apply the rules in `custom.rule` to each word in `password.list` and store the mutated results in `mut_password.list`.

```bash
$ cat password.list

password

$ hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list

$ cat mut_password.list

password
Password
passw0rd
Passw0rd
p@ssword
P@ssword
P@ssw0rd
password!
....[SNIP].......
```

Hashcat and JtR both come with pre-built rule lists that can be used for password generation and cracking. One of the most effective and widely used rulesets is `best64.rule`, which applies common transformations that frequently result in successful password guesses.

```bash
$ hashcat -a 0 -m 0 <hash> mut_password.list -r /usr/share/hashcat/rules/best64.rule
```
