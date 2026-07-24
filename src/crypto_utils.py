# crypto_utils.py
import os
import json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import config

# ------------------------------------------------------------
# Hàm tiện ích cho ECDH
# ------------------------------------------------------------
def generate_ecdh_keypair():
    """Sinh cặp khóa ECDH mới."""
    private_key = ec.generate_private_key(config.CURVE)
    public_key = private_key.public_key()
    return private_key, public_key

def get_public_key_bytes(public_key):
    """Chuyển khóa công khai sang bytes (dạng nén)."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

def deserialize_public_key(public_bytes):
    """Khôi phục khóa công khai từ bytes."""
    return ec.EllipticCurvePublicKey.from_encoded_point(config.CURVE, public_bytes)

def compute_shared_secret(private_key, peer_public_key):
    """Tính Shared Secret bằng ECDH."""
    return private_key.exchange(ec.ECDH(), peer_public_key)

# ------------------------------------------------------------
# HKDF – dẫn xuất khóa phiên
# ------------------------------------------------------------
def derive_session_key(shared_secret, salt=config.HKDF_SALT,
                       info=config.HKDF_INFO, length=config.HKDF_LENGTH):
    """Dẫn xuất khóa phiên từ Shared Secret."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(shared_secret)

# ------------------------------------------------------------
# Mã hóa / giải mã AES-GCM
# ------------------------------------------------------------
def encrypt_aes_gcm(key, plaintext, associated_data=b''):
    """Mã hóa plaintext bằng AES-GCM, trả về (nonce, ciphertext)."""
    nonce = os.urandom(config.AES_GCM_NONCE_LENGTH)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext

def decrypt_aes_gcm(key, nonce, ciphertext, associated_data=b''):
    """Giải mã AES-GCM, nếu tag không hợp lệ sẽ raise InvalidTag."""
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
    return plaintext

# ------------------------------------------------------------
# Tạo các khóa tĩnh dùng cho demo xác thực / MITM
# ------------------------------------------------------------
# Khóa hợp pháp của Server (dùng để xác thực)
legitimate_private_key = ec.generate_private_key(config.CURVE)
legitimate_public_key = legitimate_private_key.public_key()

# Khóa của kẻ tấn công (giả mạo Server)
attacker_private_key = ec.generate_private_key(config.CURVE)
attacker_public_key = attacker_private_key.public_key()

# Khóa tĩnh của Client (dùng khi chọn Static Keys)
client_static_private_key = ec.generate_private_key(config.CURVE)
client_static_public_key = client_static_private_key.public_key()

def get_public_key_fingerprint(public_key):
    """Tính SHA-256 fingerprint của khóa công khai."""
    pub_bytes = get_public_key_bytes(public_key)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(pub_bytes)
    return digest.finalize()

# Fingerprint của Server hợp pháp (Client sẽ kiểm tra)
LEGITIMATE_FINGERPRINT = get_public_key_fingerprint(legitimate_public_key)

# ------------------------------------------------------------
# Hàm tạo dữ liệu cảm biến giả lập
# ------------------------------------------------------------
def generate_sensor_data():
    import time, random
    return {
        "temperature": round(random.uniform(20.0, 35.0), 2),
        "humidity": round(random.uniform(40.0, 80.0), 2),
        "timestamp": time.time()
    }