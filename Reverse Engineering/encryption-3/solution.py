def solve_encryption_3():
    # 1. 从 GDB 提取的 28 个字节数据 (地址 0x404030)
    # 数据来源: x/28xb 0x404030
    target_data = [
        0x74, 0x78, 0x77, 0x7f, 0x6b, 0x72, 0x3b, 0x6f,
        0x68, 0x77, 0x74, 0x7a, 0x82, 0x81, 0x6e, 0x79,
        0x70, 0x77, 0x84, 0x89, 0x76, 0x82, 0x8a, 0x77,
        0x7f, 0x8f, 0x89, 0x99
    ]

    flag = ""

    # 2. 根据逆向公式进行计算: input[i] = target[i] - i - 1
    for i in range(len(target_data)):
        # 执行减法并转换为 ASCII 字符
        original_char = chr(target_data[i] - i - 1)
        flag += original_char

    print(f"[*] = Flag: {flag}")
    print(f"[*] = length: {len(flag)}")

if __name__ == "__main__":
    solve_encryption_3()