import ssl
import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from ecdsa import SECP521r1
from ecdsa.ellipticcurve import Point

# 加载客户端证书和私钥
def load_client_cert(cert_file, key_file):
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    return context

# 建立安全连接
def create_secure_connection(host, port, context):
    connection = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host)
    connection.connect((host, port))
    return connection

# 生成私钥
def generate_private_key(n):
    while True:
        # 生成随机的 66 字节整数（足够覆盖 521 位）
        random_bytes = get_random_bytes(66)
        private_key = int.from_bytes(random_bytes, 'big') % n
        # 检查私钥是否在范围内
        if private_key > 0 and private_key > (1 << 511):  # 确保私钥大于 2^511
            return private_key

# 生成 AES 密钥
def generate_aes_key(shared_key):
    # 将共享密钥转换为字节并取前 32 字节
    return shared_key.x.to_bytes(32, byteorder='big')

# 加密数据
def encrypt_data(aes_key, data):
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return cipher.nonce + tag + ciphertext

# 解密数据
def decrypt_data(aes_key, data):
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

def main():
    host = 'localhost'  # 服务器地址
    port = 10000        # 服务器端口
    cert_file = 'D:/TSL/client_cert.pem'  # 客户端证书文件路径
    key_file = 'D:/TSL/client_private.pem'  # 客户端私钥文件路径
    
    # 加载证书和私钥
    context = load_client_cert(cert_file, key_file)
    
    # 创建与服务器的安全连接
    connection = create_secure_connection(host, port, context)
    
    # 创建曲线和生成私钥
    curve = SECP521r1.curve
    n = curve.order
    n_A = generate_private_key(n)
    G = SECP521r1.generator
    Q_A = n_A * G

    # 假设 B 端发送给 A 的 Q_B，实际情况应从网络接收
    Q_B_from_B = Point(curve, 54321, 98765)  # 示例值
    shared_key = n_A * Q_B_from_B  # 计算共享密钥

    # 使用密钥协商生成 AES 密钥
    aes_key = generate_aes_key(shared_key)

    # 加密数据并发送
    message = 'Hello, Server!'
    encrypted_data = encrypt_data(aes_key, message)
    connection.sendall(encrypted_data)
    
    # 接收并解密数据
    encrypted_response = connection.recv(1024)
    decrypted_message = decrypt_data(aes_key, encrypted_response)
    print(f"Received decrypted message: {decrypted_message}")
    
    # 关闭连接
    connection.close()

if __name__ == '__main__':
    main()

