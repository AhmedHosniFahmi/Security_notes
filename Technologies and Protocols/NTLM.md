### Content



---

- NTLM credentials are based on domain name, a user name provided by the user during the interactive logon process, and a one-way [hash](https://learn.microsoft.com/en-us/windows/win32/secgloss/h-gly) of the user's password.
- NTLM uses an encrypted challenge/response protocol to authenticate a user without sending the user's password over the wire.
- The system requesting authentication must perform a calculation that proves it has access to the secured NTLM credentials.

Interactive and noninteractive authentication: 

- Interactive NTLM authentication over a network typically involves two systems:
	- A client system, where the user is requesting authentication
	- A domain controller, where information related to the user's password is kept.
- Noninteractive authentication, which may be required to permit an already logged-on user to access a resource such as a server application, typically involves three systems
	- A client
	- A server
	- A domain controller that does the authentication calculations on behalf of the server.

### Authentication Process

1. (Interactive authentication only) A user accesses a client computer and provides a domain name, user name, and password. The client computes a cryptographic [hash](https://learn.microsoft.com/en-us/windows/win32/secgloss/h-gly) of the password and discards the actual password.
2. The client sends the user name to the server (in [plaintext](https://learn.microsoft.com/en-us/windows/win32/secgloss/p-gly)).
3. The server generates a 8-byte random number, called a _challenge_ or [nonce](https://learn.microsoft.com/en-us/windows/win32/secgloss/n-gly), and sends it to the client.
4. The client encrypts this challenge with the hash of the user's password and returns the result to the server. This is called the _response_.
5. (Noninteractive authentication) The server sends the following three items to the domain controller:
    - User name
    - Challenge sent to the client
    - Response received from the client
6. The domain controller uses the user name to retrieve the hash of the user's password from the Security Account Manager database. It uses this password hash to encrypt the challenge.
7. The domain controller compares the encrypted challenge it computed (in step 6) to the response computed by the client (in step 4). If they are identical, authentication is successful.

Your application should not access the NTLM [security package](https://learn.microsoft.com/en-us/windows/win32/secgloss/s-gly) directly; instead, it should use the [Negotiate](https://learn.microsoft.com/en-us/windows/win32/secgloss/n-gly) security package. Negotiate allows your application to take advantage of more advanced [security protocols](https://learn.microsoft.com/en-us/windows/win32/secgloss/s-gly) if they are supported by the systems involved in the authentication. Currently, the Negotiate security package selects between [Kerberos](https://learn.microsoft.com/en-us/windows/win32/secgloss/k-gly) and NTLM. Negotiate selects Kerberos unless it cannot be used by one of the systems involved in the authentication.