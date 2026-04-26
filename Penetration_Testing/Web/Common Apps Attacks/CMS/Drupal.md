### Content

- [Enumeration](#enumeration)
	- [Manual](#manual)
	- [Automated](#automated)
- [Attacks](#attacks)
	- [RCE](#rce)
		- [Abusing PHP Filter Module](#abusing-php-filter-module)

> [!Note]
> 
> - See `/CHANGELOG.txt`, `/README.txt`, `/robots.txt`
> - Drupal has three types of users by default:
> 	- `Administrator`: Complete control over the Drupal website.
> 	- `Authenticated User`: Can log in to the website and perform operations based on their permissions.
> 	- `Anonymous`: All website visitors are designated as anonymous. By default, only allowed to read posts.

---
### Enumeration
##### Manual

```bash
# Footprinting and discovering drupal
$ curl -s http://FQDN | grep Drupal
# Drupal indexes its content using nodes
$ for i in {0..100}; do curl -s "http://FQDN/node/$i"; done 

# Version
$ curl -s http://FQDN/CHANGELOG.txt

```

##### Automated

Installing and using `droopescan`

```bash
git clone https://github.com/droope/droopescan.git
cd droopescan
# Replace the following
# In the Dockerfile {"FROM python:3" : "FROM python:3.7-slim"}
# In the setup.py {"pystache" : "pystache==0.5.4"}
sudo docker build -t droope/droopescan .

# Scanning a website
sudo docker run --rm --add-host=<FQDN>:<IP> droope/droopescan scan drupal --url http://<FQDN>/ -t 50
```

---
### Attacks
#### RCE
##### Abusing PHP Filter Module

In old Drupal versions (before version 8), log in as an admin and enable the `PHP filter` module, would allows embedded PHP code/snippets to be evaluated.

Open `Modules` -> Active `PHP filter` module -> On the top left click on `Add content` -> Choose `Basic page` -> specify a title and fill the body with the PHP shell -> Change the `Text format` in the bottom to be `PHP code` -> Clicking save will redirect us to the page we created -> Now we can browse the page with the command we want.

If the `Text Format` has no `PHP code`, add it:

<img src="/assets/drupal_enable_php_filter.png" style="display: block; margin:auto; height:500;">

> From version 8 onwards, the [PHP Filter](https://www.drupal.org/project/php/releases/8.x-1.1) module is not installed by default. To leverage this functionality, we would have to download and install the module ourselves.

```bash
wget https://ftp.drupal.org/files/projects/php-8.x-1.1.tar.gz
```


