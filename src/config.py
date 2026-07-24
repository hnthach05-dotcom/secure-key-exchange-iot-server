# config.py
import os
from cryptography.hazmat.primitives.asymmetric import ec

HOST = '127.0.0.1'
PORT = 8443

# Đường cong Elliptic Curve sử dụng cho ECDH
CURVE = ec.SECP256R1()

# Tham số HKDF
HKDF_SALT = b'iot_secure_salt'
HKDF_INFO = b'iot-session-key'
HKDF_LENGTH = 32  # 256-bit key cho AES-GCM

# Tham số AES-GCM
AES_GCM_NONCE_LENGTH = 12
AES_GCM_TAG_LENGTH = 16  # mặc định

# Đường dẫn lưu key tĩnh (nếu muốn lưu file)
KEY_DIR = "keys"
os.makedirs(KEY_DIR, exist_ok=True)