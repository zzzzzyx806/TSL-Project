import ssl
import socket
from Crypto.Cipher import AES
from ecdsa import SECP521r1
from ecdsa.ellipticcurve import Point
from Crypto.Random import get_random_bytes

# 加载服务器证书和私钥
def load_server_cert(cert_file, key_file):
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    context.verify_mode = ssl.CERT_OPTIONAL  # 可选的客户端证书验证
    return context

# 建立安全连接
def create_secure_server_socket(host, port, context):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Server listening on {host}:{port}")
    
    secure_socket = context.wrap_socket(server_socket, server_side=True)
    connection, address = secure_socket.accept()
    print(f"Connection from {address}")
    
    return connection

# 生成 AES 密钥
def generate_aes_key(shared_key):
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

# 计算共享密钥
def compute_shared_key(private_key, public_key):
    return private_key * public_key

def main():
    host = 'localhost'  # 服务器地址
    port = 10000        # 服务器端口
    cert_file = 'D:/TSL/server_cert.pem'  # 服务器证书文件路径
    key_file = 'D:/TSL/server_private.pem'  # 服务器私钥文件路径
    
    # 加载证书和私钥
    context = load_server_cert(cert_file, key_file)
    
    # 创建与客户端的安全连接
    connection = create_secure_server_socket(host, port, context)
    
    # 创建曲线和生成私钥
    curve = SECP521r1.curve
    n = curve.order
    G = SECP521r1.generator
    n_B = get_random_bytes(66)  # 生成私钥的方式可以根据需求修改
    n_B = int.from_bytes(n_B, 'big') % n
    Q_B = n_B * G
    
    # 发送 B 端的公钥给客户端
    connection.sendall(Q_B.to_bytes(66, 'big'))  # 假设客户端能够接收 66 字节的公钥
    
    # 接收客户端发送的加密数据（假设消息在连接上被加密了）
    encrypted_data = connection.recv(1024)
    
    # 获取客户端发送的公钥 Q_A
    Q_A_from_A = Point(curve, int.from_bytes(encrypted_data[:66], 'big'), 0)  # 解析客户端公钥
    
    # 计算共享密钥
    shared_key = compute_shared_key(n_B, Q_A_from_A)
    
    # 使用共享密钥生成 AES 密钥
    aes_key = generate_aes_key(shared_key)
    
    # 解密收到的数据
    decrypted_message = decrypt_data(aes_key, encrypted_data[66:])  # 跳过前 66 字节的公钥
    print(f"Received decrypted message: {decrypted_message}")
    
    # 对响应消息进行加密并发送给客户端
    response_message = 'Hello, Client!'
    encrypted_response = encrypt_data(aes_key, response_message)
    connection.sendall(encrypted_response)
    
    # 关闭连接
    connection.close()

if __name__ == '__main__':
    main()
