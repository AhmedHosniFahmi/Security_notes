### Content

- [Overview](#overview)
- [View Service Permissions](#view-service-permissions)
- [Example](#example)

> [Resource.1](https://www.winhelponline.com/blog/view-edit-service-permissions-windows/)
---
#### Overview

The `Security Descriptor Definition Language (SDDL)` output can contain DACL as well as SACL entries. A DACL identifies users and groups who are allowed or denied access to an object. The SACL defines how access is audited on an object. SACL enables administrators to log attempts to access a secured object.

---
###### View Service Permissions

using `SC` utility in windows command line`sc.exe sdshow [service_short_name]`.

```CMD
C:\> sc.exe sdshow schedule

D:(A;;CCLCSWLORC;;;**AU**)(A;;CCLCSWRPDTLOCRRCWDWO;;;**BA**)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;**SY**)(A;;CCLCSWLORC;;;**BU**)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;**WD**)
```

The above output shows the Task Scheduler service’s permission entries in `Security Descriptor Definition Language (SDDL)` format.

---
#### Example

let’s cover only the DACL (denoted by the D: at the beginning.) SACL is for a different purpose and is out of the scope this document.

`D:(A;;CCLCSWLORC;;;**AU**)(A;;CCLCSWRPDTLOCRRCWDWO;;;**BA**)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;**SY**)(A;;CCLCSWLORC;;;**BU**)`

here’s the meaning of the security descriptors for Task Scheduler service:

| D:  | Discretionary ACL (DACL)          |
| --- | --------------------------------- |
| S:  | System Access Control List (SACL) |

| ACE type | Meaning        |
| -------- | -------------- |
| A        | Access Allowed |

| ACE flags string | Meaning                      |                                                                                                       |
| ---------------- | ---------------------------- | ----------------------------------------------------------------------------------------------------- |
| CC               | SERVICE_QUERY_CONFIG         | Query the SCM for the service configuration                                                           |
| LC               | SERVICE_QUERY_STATUS         | Query the SCM the current status of the service                                                       |
| SW               | SERVICE_ENUMERATE_DEPENDENTS | [List dependent services](https://www.winhelponline.com/blog/how-to-remove-unwanted-service/)         |
| LO               | SERVICE_INTERROGATE          | Query the service its current status                                                                  |
| RC               | READ_CONTROL                 | Query the security descriptor of the service                                                          |
| RP               | SERVICE_START                | Start the service                                                                                     |
| DT               | SERVICE_PAUSE_CONTINUE       | Pause/Resume the service                                                                              |
| CR               | SERVICE_USER_DEFINED_CONTROL |                                                                                                       |
| WD               | WRITE_DAC                    | Change the permissions of the service                                                                 |
| WO               | WRITE_OWNER                  | Change the owner in the object’s security descriptor.                                                 |
| WP               | SERVICE_STOP                 | Stop the service                                                                                      |
| DC               | SERVICE_CHANGE_CONFIG        | Change service configuration                                                                          |
| SD               | DELETE                       | The right to [delete the service](https://www.winhelponline.com/blog/how-to-remove-unwanted-service/) |

For more information, check out [ACE Strings](https://docs.microsoft.com/en-us/windows/win32/secauthz/ace-strings) and [Service Security and Access Rights](https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) 

The last two characters after the ACE strings represent the security principal assigned with these permissions.

| Abbreviation | Security Principal      |
| ------------ | ----------------------- |
| AU           | Authenticated Users     |
| BA           | Built-in administrators |
| SY           | Local System            |
| BU           | Built-in users          |
| WD           | Everyone                |

Let’s see what rights the “built-in administrators” group has, as per this SDDL.

```SDDL
D:
(A;;CCLCSWLORC;;;AU)
(A;;CCLCSWRPDTLOCRRCWDWO;;;BA)
(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)
(A;;CCLCSWLORC;;;BU)
S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)
```

The **built-in administrators** (`BA`) group has the following rights:

| **ACE flags string** |                              |                                                                                               |
| -------------------- | ---------------------------- | --------------------------------------------------------------------------------------------- |
| CC                   | SERVICE_QUERY_CONFIG         | Query the SCM for the service configuration                                                   |
| LC                   | SERVICE_QUERY_STATUS         | Query the SCM the current status of the service                                               |
| SW                   | SERVICE_ENUMERATE_DEPENDENTS | [List dependent services](https://www.winhelponline.com/blog/how-to-remove-unwanted-service/) |
| LO                   | SERVICE_INTERROGATE          | Query the service its current status                                                          |
| RC                   | READ_CONTROL                 | Query the security descriptor of the service                                                  |
| RP                   | SERVICE_START                | Start the service                                                                             |
| DT                   | SERVICE_PAUSE_CONTINUE       | Pause/Resume the service                                                                      |
| CR                   | SERVICE_USER_DEFINED_CONTROL |                                                                                               |
| WD                   | WRITE_DAC                    | Change the permissions of the service                                                         |
| WO                   | WRITE_OWNER                  | Change the ownership of the service                                                           |

BA group doesn’t have the permissions to stop (WP), change the service configuration (DC), or delete the service (SD).

Whereas the Local System account (SY) has full permissions: `(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)`

| **ACE flags string** |                              |                                                                                               |
| -------------------- | ---------------------------- | --------------------------------------------------------------------------------------------- |
| CC                   | SERVICE_QUERY_CONFIG         | Query the SCM for the service configuration                                                   |
| LC                   | SERVICE_QUERY_STATUS         | Query the SCM the current status of the service                                               |
| SW                   | SERVICE_ENUMERATE_DEPENDENTS | [List dependent services](https://www.winhelponline.com/blog/how-to-remove-unwanted-service/) |
| LO                   | SERVICE_INTERROGATE          | Query the service its current status                                                          |
| RC                   | READ_CONTROL                 | Query the security descriptor of the service                                                  |
| RP                   | SERVICE_START                | Start the service                                                                             |
| DT                   | SERVICE_PAUSE_CONTINUE       | Pause/Resume the service                                                                      |
| CR                   | SERVICE_USER_DEFINED_CONTROL |                                                                                               |
| WD                   | WRITE_DAC                    | Change the permissions of the service                                                         |
| WO                   | WRITE_OWNER                  | Change the ownership of the service                                                           |
| **WP**               | SERVICE_STOP                 | Stop the service                                                                              |
| **DC**               | SERVICE_CHANGE_CONFIG        | Change service configuration                                                                  |
| **SD**               | DELETE                       | The right to delete the service                                                               |

As you see, the Local System user has the full permissions ([SERVICE_ALL_ACCESS](https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)), and it can do anything with this service.