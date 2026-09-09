import angr
import claripy
import base64
import os
import re
import logging
import time
from pwn import *

# Suppress unnecessary angr logging
logging.getLogger('angr').setLevel('ERROR')

def get_input_length_dynamically(p):
    """Dynamically determine the byte length required by fread"""
    fread_plt_addr = p.loader.main_object.plt.get('fread')
    p.analyses.CFGFast()
    main_func = p.kb.functions.get('main')
    if not main_func: return None

    for block in main_func.blocks:
        for i, ins in enumerate(block.capstone.insns):
            if ins.mnemonic == 'call':
                try:
                    target = int(ins.op_str, 16)
                    if target == fread_plt_addr:
                        # Trace backward to find rdx/edx assignment (Arg 3: length)
                        for j in range(i - 1, -1, -1):
                            prev = block.capstone.insns[j]
                            if prev.mnemonic == 'mov' and ('edx' in prev.op_str or 'rdx' in prev.op_str):
                                match = re.search(r'0x[0-9a-fA-F]+|[0-9]+', prev.op_str)
                                if match: return int(match.group(), 0)
                except: continue
    return None

def solve_challenge(binary_path):
    print(f"[*] Analyzing: {binary_path}")
    p = angr.Project(binary_path, auto_load_libs=False)
    
    input_len = get_input_length_dynamically(p)
    print(f"[+] Identified input length: {input_len}")

    # 1. Modeling: Create symbolic variables only for the identified input length
    input_data = claripy.BVS('input_data', input_len * 8)
    state = p.factory.entry_state(stdin=input_data)
    simgr = p.factory.simulation_manager(state)

    print("[*] Computing paths...")
    # Explore paths based on stdout content to handle dynamic addresses
    simgr.explore(
        find=lambda s: b"OK" in s.posix.dumps(1),
        avoid=lambda s: b"Invalid" in s.posix.dumps(1)
    )

    if simgr.found:
        sol_state = simgr.found[0]
        # Evaluate and return the precise answer
        return sol_state.solver.eval(input_data, cast_to=bytes)
    return None

def start_automation():
    HOST = 'svtctf.m0lecon.it'
    PORT = 13400 

    io = remote(HOST, PORT)

    try:
        for round_idx in range(1, 31):
            print(f"\n{'='*20} ROUND {round_idx} / 30 {'='*20}")
            
            # 1. Receive and save Base64 encoded binary
            io.recvuntil(b"-----BEGIN BINARY-----")
            b64_content = io.recvuntil(b"-----END BINARY-----", drop=True).strip()
            
            challenge_bin = f"challenge_current.bin"
            with open(challenge_bin, "wb") as f:
                f.write(base64.b64decode(b64_content))
            os.chmod(challenge_bin, 0o755)
            
            # 2. Solving process
            answer = solve_challenge(challenge_bin)
            
            if answer:
                print(f"[!] Solution found: {answer} (Length: {len(answer)})")
                
                # 3. Interaction: Send the solution precisely
                io.recvuntil(b"Enter the key: ")
                
                # Send answer (without newline by default)
                io.send(answer)
                
                # If the environment requires a newline to trigger processing, 
                # uncomment the following line:
                # io.send(b'\n') 
                
                # 4. Handle server feedback
                try:
                    res = io.recvline(timeout=3).decode().strip()
                    # If server echoes the input or returns empty, read the next line
                    if answer.decode() in res or not res:
                        res = io.recvline(timeout=3).decode().strip()
                    
                    print(f"[*] Server Response: {res}")
                    
                    if "OK" in res:
                        if os.path.exists(challenge_bin): os.remove(challenge_bin)
                    else:
                        print("[-] Server rejected the key. Stopping.")
                        break
                except Exception:
                    print("[-] Timed out waiting for feedback.")
                    break
            else:
                print("[-] Solving failed (path not found).")
                break
        
        # Enter interactive mode after 30 rounds to retrieve the Flag
        io.interactive()

    except Exception as e:
        print(f"[-] Error occurred: {e}")
    finally:
        io.close()

if __name__ == "__main__":
    start_automation()