import angr
import claripy
import base64
import os
from pwn import *

# Server connection configuration
HOST = 'svtctf.m0lecon.it'
PORT = 13418

def solve_challenge(binary_path):
    """
    Analyzes the binary and finds the correct 16-byte key using angr.
    """
    # Initialize the angr project
    # auto_load_libs=False prevents loading shared libraries to speed up analysis
    proj = angr.Project(binary_path, auto_load_libs=False)
    
    # 1. Dynamic Hooking: Bypass 'useless_function'
    # This function might contain junk code or infinite loops that slow down symbolic execution.
    # We replace it with a stub that simply returns immediately.
    useless = proj.loader.find_symbol('useless_function')
    if useless:
        proj.hook(useless.rebased_addr, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
    
    # 2. CFG Generation and String Cross-Reference (XRef) Localization
    # CFGFast performs a quick static analysis to map out the program's functions.
    proj.analyses.CFGFast()
    
    def get_addr(s):
        """Helper to find the instruction address that references a specific string."""
        try:
            # Locate the string in the binary's memory
            addr = next(proj.loader.memory.find(s.encode()))
            # Look up which instruction references this string's address (XRef)
            return next(iter(proj.kb.xrefs.get_xrefs_by_dst(addr))).ins_addr
        except: 
            return None

    # Automatically identify the "Success" and "Failure" code paths by searching for printed strings
    find_addr = get_addr("Correct!")
    avoid_addr = get_addr("Wrong!")
    
    if not find_addr: 
        return None

    # 3. Symbolic Execution Setup
    # Create a symbolic Bit Vector (BVS) of 16 bytes (128 bits) to represent the flag/key
    flag = claripy.BVS('flag', 16 * 8)
    
    # Define the initial state starting at the program entry point, with stdin redirected to our symbolic BVS
    state = proj.factory.entry_state(stdin=flag)
    
    # Initialize the Simulation Manager to handle path exploration
    simgr = proj.factory.simulation_manager(state)
    
    # Explore the binary: try to reach find_addr while discarding paths that hit avoid_addr
    simgr.explore(find=find_addr, avoid=avoid_addr)
    
    # If a path to the "Correct!" message is found, solve the constraints for the symbolic input
    if simgr.found:
        # Evaluate the symbolic variable 'flag' into concrete bytes
        return simgr.found[0].solver.eval(flag, cast_to=bytes)[:16]
    
    return None

# --- Main Automation Loop ---

# Establish remote connection to the challenge server
io = remote(HOST, PORT)

for i in range(1, 31): # Solve 30 rounds as required by the challenge
    log.info(f"Challenging Round {i}/30...")
    
    # Extract the Base64-encoded binary embedded between markers
    io.recvuntil(b"-----BEGIN BINARY-----\n")
    b64_data = io.recvuntil(b"-----END BINARY-----", drop=True)
    
    # Decode and save the binary to disk
    with open('current_bin', 'wb') as f:
        f.write(base64.b64decode(b64_data))
    
    # Grant execution permissions to the saved file
    os.chmod('current_bin', 0o755)
    
    # Solve the current binary using the angr-based logic
    result = solve_challenge('./current_bin')
    
    if result:
        log.success(f"Key found: {result.hex()}")
        # Send the raw bytes of the key back to the server
        io.send(result)
    else:
        log.error("Failed to solve the binary!")
        break

# Once all rounds are finished, switch to manual interaction to read the final flag
io.interactive()

# Flag obtained: svt{turn5_0ut_us3l3s5_funct10n_1s_r34lly_us3l3ss_c32uzhoi8WAWIj3j}