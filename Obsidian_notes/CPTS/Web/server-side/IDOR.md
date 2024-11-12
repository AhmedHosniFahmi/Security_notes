### Content
* [[#Overview]]
* [[#Identifying IDORs]]
	* URL Parameters & APIs
	* AJAX Calls
	* Compare User Roles
---
## Overview
[Insecure Direct Object References (IDOR)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
- Cause: IDOR vulnerabilities arise when applications reference objects directly (e.g., using unique IDs in URLs) without verifying that the user has permission to access or modify those objects.
- Exploitation: Attackers manipulate parameters in requests (like changing a user ID or file ID in a URL) to access or modify resources that they should not be able to access. For example, changing `https://example.com/user/123` to `https://example.com/user/124` could allow one user to view another user's profile.
- Impact
    - Unauthorized Data Access
    - Data Modification
    - Privilege Escalation
- Prevention:
    - Access Control Checks: Enforce access controls on the server side, validating that users have permission to access specific objects.
    - Avoid Direct References: Use indirect references (e.g., mapped tokens) to objects instead of predictable IDs that users can manipulate.
    - Logging and Monitoring: Track and log access to sensitive resources to detect and respond to unusual access patterns.
---
## Identifying IDORs
- **URL Parameters & APIs**
	- Whenever we receive a specific file or resource, we should study the HTTP requests to look for URL parameters or APIs with an object reference (e.g. `?uid=1` or `?filename=file_1.pdf`).
	- Mostly found in URL parameters or APIs but may also be found in other HTTP headers, like `cookies`.
- **AJAX Calls**
	- We may also be able to identify unused parameters or APIs in the front-end code in the form of JavaScript AJAX calls. EX:
		``` JS
		function changeUserPassword() {
		    $.ajax({
		        url:"change_password.php",
		        type: "post",
		        dataType: "json",
		        data: {uid: user.uid, password: user.password, is_admin: is_admin},
		        success:function(result){
		            //
		        }
		    });
		}
		```
* Compare User Roles 
	1. Register multiple users.
	2. Compare their HTTP requests and object references.
	3. Understand how the URL parameters and unique identifiers are being calculated.
	4. Calculate them for other users to gather their data.
---

