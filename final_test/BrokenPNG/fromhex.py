import base64
from Crypto.Cipher import AES

def pkcs7_unpad(data: bytes) -> bytes:
    """移除PKCS#7填充"""
    padding_length = data[-1]
    if padding_length < 1 or padding_length > 16:
        raise ValueError("无效的填充")
    if data[-padding_length:] != bytes([padding_length]) * padding_length:
        raise ValueError("无效的填充")
    return data[:-padding_length]

# 修改decrypt_aes_ecb函数，增加调试信息
def decrypt_aes_ecb(ciphertext_base64: str, key: bytes) -> str:
    try:
        ciphertext = base64.b64decode(ciphertext_base64)
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext = cipher.decrypt(ciphertext)
        
        # 调试输出
        print(f"解密后字节: {plaintext.hex()}")
        
        # 尝试不同解码方式
        try:
            return plaintext.decode('latin-1')
        except UnicodeDecodeError:
            print("尝试其他解码方式...")
            try:
                return plaintext.decode('latin-1')  # 所有字节都能转为latin-1
            except:
                print("无法解码为字符串，返回原始字节")
                return plaintext
                
    except Exception as e:
        print(f"解密失败: {e}")
        return None

# 示例使用
key = bytes.fromhex('5ec853e267b28fc3efbe1b3032a241c5')  # 16字节密钥
ciphertext_base64 = "fwDnVMscpJfJsfinygeZBP+rBonh+kKNpqyp1YE1Dvi6cpVMYKwpRctI+xVk6J1lPqwO3m1t0ozVTZdCe70BPkC85q3VmAfE1kc3oxz6X2w="

plaintext = decrypt_aes_ecb(ciphertext_base64, key)
if plaintext:
    print(f"明文: {plaintext}")