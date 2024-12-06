### Content
- [LDAP](#ldap)
- [ADFS](#adfs)
---
# LDAP
Lightweight Directory Access Protocol it's a standardized protocol used for accessing and maintaining distributed directory information services over an Internet Protocol (IP) network. Its key characteristics:
1. Purpose
	- LDAP is primarily used for storing and organizing information about users, groups, systems, and network resources in a hierarchical, tree-like structure
	- It serves as a centralized repository for authentication and authorization information
2. Key Features
	- Allows searching and modifying directory entries
	- Supports secure communication through SSL/TLS encryption
	- Provides a lightweight alternative to heavier directory service protocols
	- Widely used in enterprise environments for managing user accounts and access control
3. Common Use Cases
	- User authentication for networks and applications
	- Email address lookups
	- Storing organizational information
	- Managing network resources and permissions
	- Single sign-on (SSO) implementations
4. Technical Details
	- Uses a client-server model
	- Operates on a hierarchical data model called a Directory Information Tree (DIT)
	- Defined by RFC (Request for Comments) standards
	- Commonly implemented through services like Microsoft Active Directory and OpenLDAP
---
# ADFS
Active Directory Federation Services is a software component developed by Microsoft that provides single sign-on (SSO) capabilities and helps securely share digital identity and access rights across organizational boundaries. Its key characteristics:
- Allows users to access multiple applications using a single set of credentials
- Facilitates authentication and authorization across different networks and domains
- Provides authentication services for web-based applications
- Supports various authentication methods, including multi-factor authentication. (ex `SAML`, `OAuth`)
- Works as a security token service
- Uses claims-based authentication
- Integrates closely with Active Directory
- Enhances security by centralizing authentication
- Supports hybrid and cloud identity scenarios
- Requires Windows Server with ADFS role installed
- Needs proper network configuration and security planning
- Requires careful design of trust relationships and claims rules
---
