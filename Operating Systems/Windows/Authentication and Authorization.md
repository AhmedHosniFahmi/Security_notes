### Content

- [Authorization](#authorization)
	- [Security identifiers](#security-identifiers)
	- [Access tokens](#access-tokens)
	- [Security descriptors and access control lists](#security-descriptors-and-access-control-lists)
	- [Permissions](#permissions)
	- [UAC](#uac)

---
# Authorization

The following diagram illustrates the Windows authorization and access control process. In the diagram, the subject (a process that's initiated by a user) attempts to access an object, such as a shared folder. The information in the user’s access token is compared to the access control entries (ACEs) in the object’s security descriptor, and the access decision is made. The SIDs of security principals are used in the user’s access token and in the ACEs in the object’s security descriptor.

<img src="/assets/authorization-and-access-control-process.png" width="65%" height="70%" style="display: block; margin:auto;">

### Security identifiers

Each time a user signs in, the system creates an access token for that user. The access token contains the user’s SID, user rights, and the SIDs for groups that the user belongs to. This token provides the security context for whatever actions the user performs on that computer.
[More Details Here](%2E/SIDs.md)
### Access tokens

An access token is a protected object that contains information about the identity and user rights that are associated with a user account.

When a user signs in interactively or tries to make a network connection to a computer running Windows, the sign-in process authenticates the user’s credentials.

- If authentication is successful, the process returns a SID for the user and a list of SIDs for the user’s security groups. The Local Security Authority (LSA) on the computer uses this information to create an access token (in this case, the primary access token). This includes the SIDs that are returned by the sign-in process and a list of user rights that are assigned by the local security policy to the user and to the user’s security groups.
- After the LSA creates the primary access token, a copy of the access token is attached to every thread and process that executes on the user’s behalf. Whenever a thread or process interacts with a securable object or tries to perform a system task that requires user rights, the operating system checks the access token that's associated with the thread to determine the level of authorization.
- There are two kinds of access tokens:
	- `Primary Token`: A primary access token is typically assigned to a process to represent the default security information for that process.
	- `Impersonation Token`: Used for client and server scenarios. Impersonation tokens enable a thread to run in a security context that differs from the security context of the process that owns the thread.

### Security descriptors and access control lists

A security descriptor is a data structure that's associated with each securable object.
All objects in Active Directory and all securable objects on a local computer or on the network have security descriptors to help control access to the objects.

Security descriptors include information about who owns an object, who can access it and in what way, and what types of access are audited. Security descriptors contain the access control list (ACL) of an object, which includes all the security permissions that apply to that object.
An object’s security descriptor can contain two types of ACLs:

- A discretionary access control list (DACL), which identifies the users and groups who are allowed or denied access.
- A system access control list (SACL), which controls how access is audited.

### Permissions

Permissions enable the owner of each securable object, such as a file, Active Directory object, or registry key, to control who can perform an operation or a set of operations on the object or object property. Permissions are expressed in the security architecture as ACEs.
Because access to an object is at the discretion of the object’s owner, the type of access control that's used in Windows is called discretionary access control.

Permissions vs Rights:
- Permissions are attached to objects.
- Rights apply to user accounts.
	- Administrators can assign user rights to groups or users. These rights authorize users to perform specific actions, such as signing in to a system interactively or backing up files and directories.

## UAC

User Account Control (UAC) is a Windows security feature designed to protect the operating system from unauthorized changes. When changes to the system require administrator-level permission, UAC notifies the user, giving the opportunity to approve or deny the change.

Applications that aren't designed with security settings in mind, might require more permissions to run successfully. These applications are referred to as legacy apps.

By default, both standard and administrator users access resources and execute apps in the security context of a standard user.  
When a user signs in, the system creates an access token for that user. The access token contains information about the level of access that the user is granted, including specific security identifiers (SIDs) and Windows privileges.

When an administrator logs on, two separate access tokens are created for the user: a `standard user access token` and an `administrator access token`.

<img src="/assets/uac-windows-logon-process.png" width="40%" height="40%" style="display: block; margin:auto;">
The standard user access token:

- Contains the same user-specific information as the administrator access token, but the administrative Windows privileges and SIDs are removed.
- Is used to start applications that don't perform administrative tasks (standard user apps).
- Is used to display the desktop by executing the process _explorer.exe_.
	- Explorer.exe is the parent process from which all other user-initiated processes inherit their access token.

As a result, all apps run as a standard user unless a user provides consent or credentials to approve an app to use a full administrative access token.

---




