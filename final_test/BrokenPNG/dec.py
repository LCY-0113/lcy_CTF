import os

# 已知PNG文件头
PNG_HEADER = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00 , 0x00 , 0x00 , 0x0D , 0x49 , 0x48 , 0x44 , 0x52])

def recover_key(encrypted_data):
    """从加密数据中恢复密钥"""
    key = bytearray(16)
    
    # 使用已知的PNG文件头恢复密钥的前8个字节
    for i in range(min(len(PNG_HEADER), len(encrypted_data))):
        key[i] = encrypted_data[i] ^ PNG_HEADER[i]
    
    # 对于密钥的其余部分，我们需要更多信息或猜测
    # 这里我们假设密钥的其余部分是随机的，但在实际中可能需要更多分析
    # 一个简单的方法是尝试常见的密钥模式或使用统计分析
    
    return bytes(key)

def decrypt_file(encrypted_data, key):
    """使用密钥解密数据"""
    decrypted_data = []
    
    for i in range(len(encrypted_data)):
        decrypted_data.append(encrypted_data[i] ^ key[i % len(key)])
    
    return bytes(decrypted_data)

def main():
    # 读取加密文件
    with open("broken.png", "rb") as f:
        encrypted_data = f.read()
    
    # 恢复密钥
    key = recover_key(encrypted_data)
    print(f"恢复的密钥: {key.hex()}")
    
    # 解密文件
    decrypted_data = decrypt_file(encrypted_data, key)
    
    # 保存解密后的文件
    output_file = "decrypted.png"
    with open(output_file, "wb") as f:
        f.write(decrypted_data)
    
    print(f"已解密文件并保存为: {output_file}")
    
    # 检查解密后的文件是否有效
    if decrypted_data.startswith(PNG_HEADER):
        print("解密后的文件看起来是一个有效的PNG文件")
    else:
        print("解密后的文件可能无效，可能需要更多分析")

if __name__ == "__main__":
    main()