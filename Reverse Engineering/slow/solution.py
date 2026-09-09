import os

# 1. Open the original binary file 'slow' in 'rb' (read binary) mode.
# Using 'with' ensures the file is closed automatically.
with open("slow", "rb") as f:
    data = f.read()

# 2. Define the 'Opcode' pattern we want to replace.
# In x86_64, the instruction 'call' starts with the byte 0xE8.
# The subsequent bytes are the relative offset to the nanosleep@plt address.
# From GDB output: 0x4004f7: call 0x400390 translates to b"\xe8\x94\xfe\xff\xff".
old_code = b"\xe8\x94\xfe\xff\xff"

# 3. Define the replacement code.
# 0x90 is the hex code for the NOP (No Operation) instruction.
# Since the 'call' instruction is 5 bytes long, we must provide exactly 5 NOPs 
# to keep the binary structure and subsequent instruction offsets intact.
new_code = b"\x90\x90\x90\x90\x90"

# 4. Search and Replace logic.
if old_code in data:
    # Perform a binary replacement of the call instruction with NOPs.
    new_data = data.replace(old_code, new_code)
    
    # 5. Write the modified buffer into a new executable file.
    with open("slow_patched", "wb") as f2:
        f2.write(new_data)
    
    # Set execution permissions for the new file (chmod +x).
    os.chmod("slow_patched", 0o755)
    
    print("Patch Successful! 'slow_patched' has been generated.")
    print("The nanosleep call has been neutralized.")
else:
    # If the bytes don't match, it might be due to a different compiler version
    # or the binary being modified already.
    print("Error: Target instruction pattern not found.")
    print("Please verify the hex code at address 0x4004f7.")

# Final Flag obtained after running the patched version:
# svt{w4it1ng_f0r_th3_fl4g_t0_b3_pr1nt3d_c0uld_b3_b0r1ng}