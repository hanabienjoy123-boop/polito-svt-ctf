import angr
import claripy
import base64
import os
from pwn import *

# 开启极简日志，避免干扰
context.log_level = 'info' 

def solve_one_final(filename):
    proj = angr.Project(filename, auto_load_libs=False)
    
    # 1. 动态定位地址
    print(f"[*] 正在分析符号...")
    # 定位 transform 的结束点 (is_alnum 的开始)
    is_alnum_sym = proj.loader.find_symbol('is_alnum')
    transformed_key_sym = proj.loader.find_symbol('transformed_key')
    
    if not is_alnum_sym or not transformed_key_sym:
        print("[-] 无法在符号表中找到关键点，尝试 fallback 地址")
        find_addr = 0x4005d2
        out_buffer_addr = 0x403080
    else:
        find_addr = is_alnum_sym.rebased_addr
        out_buffer_addr = transformed_key_sym.rebased_addr
        print(f"[+] 动态定位成功: Breakpoint={hex(find_addr)}, Buffer={hex(out_buffer_addr)}")

    # 2. 建立符号化状态
    flag = claripy.BVS('flag', 16 * 8)
    state = proj.factory.entry_state(stdin=flag)
    
    # 优化：初次求解先不加过于复杂的输入约束，让 Z3 跑得更快
    # 如果解出来不可见，再开启此行：
    # for c in flag.chop(8): state.add_constraints(c >= 0x20, c <= 0x7e)

    # 3. 探索路径
    simgr = proj.factory.simulation_manager(state)
    print(f"[*] 正在执行路径探索...")
    simgr.explore(find=find_addr)

    if simgr.found:
        sol_state = simgr.found[0]
        print(f"[*] 达到目标点，正在施加输出约束并求解...")
        
        # 4. 强制输出缓冲区为字母数字
        # make sure generated data only contain specific char
        res_bytes = sol_state.memory.load(out_buffer_addr, 16)
        for i in range(16):
            b = res_bytes.get_byte(i)
            sol_state.add_constraints(
                claripy.Or(
                    claripy.And(b >= ord('0'), b <= ord('9')),
                    claripy.And(b >= ord('a'), b <= ord('z')),
                    claripy.And(b >= ord('A'), b <= ord('Z'))
                )
            )
        
        # 5. 求解
        try:
            # 设置求解超时（10秒），如果太久就放弃
            return sol_state.solver.eval(flag, cast_to=bytes)[:16]
        except:
            print("[-] 求解超时或 Unsat")
            return None
    return None

# --- 主逻辑 ---
io = remote('svtctf.m0lecon.it', 13410)

for i in range(1, 31):
    log.info(f"第 {i}/30 关开始...")
    
    # 接收二进制
    io.recvuntil(b"-----BEGIN BINARY-----\n")
    raw_b64 = io.recvuntil(b"-----END BINARY-----", drop=True)
    
    # 接收提示词，清空缓冲区
    io.recvuntil(b"Enter key: ")
    
    with open('work_bin', 'wb') as f:
        f.write(base64.b64decode(raw_b64))
    os.chmod('work_bin', 0o755)

    # 极速求解
    key = solve_one_final('./work_bin')
    
    if key:
        log.success(f"成功推导 Key: {key.hex()}")
        io.send(key) # 这里建议先试试 send，如果没反应再换 sendline
        # 打印服务器反馈
        try:
            feedback = io.recvline(timeout=2).decode().strip()
            log.info(f"服务器反馈: {feedback}")
        except:
            log.warn("未收到服务器即时反馈")
    else:
        log.error("计算失败，请检查逻辑！")
        break

io.interactive()
