[BloodHound Cypher Cheatsheet](https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/)

``` bash
# If the DNS server of the domain is not in /etc/resolv.conf, you can add it or use -ns
$ bloodhound-ce-python -c All -d 'INLANEFREIGHT.LOCAL' -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 --dns-tcp

# Or add this in /etc/resolv.conf and comment other DNS resolvers
domain INLANEFREIGHT.LOCAL
nameserver 172.16.5.5


$ zip -r file.zip *.json
# sudo neo4j start to start the neo4j service
# go to localhost:7474 to set a username and a password
# user == neo4j / pass == root
# open bloodhound and click on upload data and select the zip file
```