## What Are Named Pipes?
### Definition:

Named Pipes are a Windows mechanism for **inter-process communication (IPC)**. They allow different processes—either on the same machine or over a network—to exchange data.

### Analogy:

Think of a Named Pipe as a **tunnel** between two processes. One process sends data into the tunnel (writes), and the other process reads data from it (reads).

---

## Types of Pipes:

1. **Anonymous Pipes:**
    - Temporary.
    - Only for communication between a parent and its child process.
    - Unidirectional (one-way).
    - Cannot be accessed remotely.
2. **Named Pipes:**
    - Persistent (exist as long as the server process keeps it open).
    - Have a name in the format:  
        `\\.\pipe\PipeName`
    - Support:
        - **Local communication (same machine).**
        - **Remote communication (across the network).**
    - Can be:
        - **Half-duplex:** One direction at a time.
        - **Full-duplex:** Both directions simultaneously.

---
## Named Pipes Structure:

- **Server Process:** Creates the pipe (`CreateNamedPipe()` function).
- **Client Process:** Connects to the pipe (`CreateFile()` function with pipe name).

**Example pipe name:**  
`\\.\pipe\msagent_12`

- `\\.\pipe\` = Windows namespace for pipes.
- `msagent_12` = The pipe name chosen by the program.

---
# Named Pipe Creation in C/C++ (Windows API)
## 1. Overview of Named Pipe API Functions

|Function|Description|
|---|---|
|`CreateNamedPipe()`|Create a named pipe (server-side).|
|`ConnectNamedPipe()`|Wait for a client to connect to the pipe.|
|`CreateFile()`|Client connects to the pipe (acts as open).|
|`ReadFile()`|Read data from the pipe.|
|`WriteFile()`|Write data to the pipe.|
|`DisconnectNamedPipe()`|Disconnect the client from the pipe.|
|`CloseHandle()`|Close the pipe handle (cleanup).|

## 2. Pipe Naming Convention

A pipe is addressed like this:

```plaintext
\\.\pipe\PipeName
```

- `\\.\pipe\` → Windows namespace for local named pipes.
- `PipeName` → The name you choose (e.g., `myPipe` or `msagent_12`).

---
## 3. Example: Server-Side Named Pipe

This is the **server**, which creates the pipe and waits for client connections.

```cpp
#include <windows.h>
#include <iostream>

int main() {
    const char* pipeName = R"(\\.\pipe\MyTestPipe)";

    // Create the named pipe
    HANDLE hPipe = CreateNamedPipeA(
        pipeName,                        // Pipe name
        PIPE_ACCESS_DUPLEX,              // Read/Write access
        PIPE_TYPE_MESSAGE |              // Message-type pipe
        PIPE_READMODE_MESSAGE |          // Message read mode
        PIPE_WAIT,                       // Blocking mode
        PIPE_UNLIMITED_INSTANCES,        // Max number of instances
        512, 512,                        // Output/Input buffer sizes
        0,                               // Default timeout
        NULL                             // Default security attributes
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create pipe. Error: " << GetLastError() << std::endl;
        return 1;
    }

    std::cout << "Waiting for client to connect to pipe...\n";

    // Wait for the client to connect
    BOOL connected = ConnectNamedPipe(hPipe, NULL) ?
        TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

    if (connected) {
        std::cout << "Client connected.\n";

        char buffer[128];
        DWORD bytesRead;

        // Read data from the client
        BOOL result = ReadFile(
            hPipe,              // Pipe handle
            buffer,             // Buffer to receive data
            sizeof(buffer) - 1, // Buffer size
            &bytesRead,         // Number of bytes read
            NULL                // Not overlapped
        );

        if (result) {
            buffer[bytesRead] = '\0';
            std::cout << "Received from client: " << buffer << std::endl;

            // Send response
            const char* reply = "Hello from server";
            DWORD bytesWritten;

            WriteFile(
                hPipe,
                reply,
                (DWORD)strlen(reply),
                &bytesWritten,
                NULL
            );
        } else {
            std::cerr << "ReadFile failed. Error: " << GetLastError() << std::endl;
        }
    } else {
        std::cerr << "Failed to connect to client.\n";
    }

    // Disconnect and clean up
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);

    return 0;
}
```

---

## 4. Example: Client-Side Named Pipe

This is the **client**, which connects to the server pipe.

```cpp
#include <windows.h>
#include <iostream>

int main() {
    const char* pipeName = R"(\\.\pipe\MyTestPipe)";

    // Attempt to connect to the pipe (retry if not yet available)
    while (true) {
        HANDLE hPipe = CreateFileA(
            pipeName,             // Pipe name
            GENERIC_READ | GENERIC_WRITE, // Read and write access
            0,                    // No sharing
            NULL,                 // Default security attributes
            OPEN_EXISTING,        // Opens existing pipe
            0,                    // Default attributes
            NULL                  // No template
        );

        if (hPipe != INVALID_HANDLE_VALUE) {
            std::cout << "Connected to pipe.\n";

            // Send data
            const char* message = "Hello from client";
            DWORD bytesWritten;

            WriteFile(
                hPipe,
                message,
                (DWORD)strlen(message),
                &bytesWritten,
                NULL
            );

            // Receive response
            char buffer[128];
            DWORD bytesRead;

            BOOL result = ReadFile(
                hPipe,
                buffer,
                sizeof(buffer) - 1,
                &bytesRead,
                NULL
            );

            if (result) {
                buffer[bytesRead] = '\0';
                std::cout << "Received from server: " << buffer << std::endl;
            } else {
                std::cerr << "ReadFile failed. Error: " << GetLastError() << std::endl;
            }

            CloseHandle(hPipe);
            break;
        }

        // If the pipe is busy, wait and retry
        if (GetLastError() == ERROR_PIPE_BUSY) {
            std::cout << "Pipe busy, retrying...\n";
            if (!WaitNamedPipeA(pipeName, 5000)) {
                std::cerr << "Could not open pipe: Wait timed out." << std::endl;
                return 1;
            }
        } else {
            std::cerr << "Failed to connect to pipe. Error: " << GetLastError() << std::endl;
            return 1;
        }
    }

    return 0;
}
```

---
## 5. How It Works Internally (Deep Technical Insight):

- **Server Process Flow:**
    1. Calls `CreateNamedPipe()`. This sets up a kernel object that listens for incoming connections.
    2. Calls `ConnectNamedPipe()` to block and wait for a client.
    3. Once connected, the pipe acts like a duplex communication socket—`ReadFile()` and `WriteFile()` exchange data.
- **Client Process Flow:**
    1. Calls `CreateFile()` with the full pipe name `\\.\pipe\MyTestPipe`.
    2. If successful, it opens the communication channel.
    3. Uses `ReadFile()`/`WriteFile()` to communicate with the server.
- **Kernel Behavior:**  
    Every instance of a pipe creates a separate memory buffer in kernel mode to handle that client-server pair. This is isolated per connection.

---

## 6. Offensive Security Applications:

- **Intra-process Communication:**  
    Malware components use named pipes to communicate between injected processes or different implants on the same machine.
- **Cobalt Strike Usage:**  
    Beacons on internal hosts communicate with parent Beacons over SMB named pipes (`\\.\pipe\msagent_12`), allowing lateral movement **without generating outbound network traffic.**
- **Evasion:**  
    Pipes are stealthier than TCP sockets inside the network, reducing detection surface.

---
## 7. Defensive & Detection Considerations:

- **Abnormal Pipe Names:**  
    Pipes named like `\\.\pipe\mojo_*` without Chrome, or `\\.\pipe\msagent_*` without justification, are suspect.
- **Pipe Usage Spike:**  
    A sudden increase in named pipe activity, especially with odd parent-child process relationships (`explorer.exe` spawning `rundll32.exe` with a pipe), may indicate lateral movement or malware.
- **ETW and Sysmon:**  
    Both can capture pipe creation events for monitoring.

---

## 8. Advanced Usage (Optional Expansion):

- **Over network:**  
    Named pipes can also be accessed remotely using UNC paths:
    
    ```plaintext
    \\hostname\pipe\pipename
    ```
    
    This enables C2 over SMB (common in internal pivoting).
- **Security Descriptors:**  
    You can restrict who can access the pipe via custom ACLs (`SECURITY_ATTRIBUTES`).
- **Asynchronous IO:**  
    Pipes can be set for **non-blocking asynchronous communication**, useful for complex multithreaded malware or implants.

---