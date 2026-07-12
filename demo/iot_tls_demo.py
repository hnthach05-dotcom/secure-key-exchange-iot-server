from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

print("=" * 60)
print(" SECURE KEY EXCHANGE BETWEEN IOT DEVICE AND SERVER")
print("=" * 60)

# =========================
# Generate ECC Key Pair
# =========================

# IoT Device
iot_private_key = ec.generate_private_key(ec.SECP256R1())
iot_public_key = iot_private_key.public_key()

# Server
server_private_key = ec.generate_private_key(ec.SECP256R1())
server_public_key = server_private_key.public_key()

print("\n[1] ECC key pairs generated successfully.")
print("IoT Device : Private Key + Public Key")
print("Server     : Private Key + Public Key")

# =========================
# ECDH Key Exchange
# =========================

# IoT Device tạo Shared Secret
iot_shared_secret = iot_private_key.exchange(
    ec.ECDH(),
    server_public_key
)

# Server tạo Shared Secret
server_shared_secret = server_private_key.exchange(
    ec.ECDH(),
    iot_public_key
)

print("\n[2] Shared Secret Generated")

print("IoT Shared Secret:")
print(iot_shared_secret.hex())

print("\nServer Shared Secret:")
print(server_shared_secret.hex())

print("\nShared Secret Match:",
      iot_shared_secret == server_shared_secret)

# =========================
# Derive Session Key (HKDF)
# =========================

session_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"IoT Secure Session",
).derive(iot_shared_secret)

print("\n[3] Session Key Generated")

print("Session Key:")
print(session_key.hex())

# =========================
# Encrypt Sensor Data
# =========================

# Tạo đối tượng AES-GCM với Session Key
aesgcm = AESGCM(session_key)

# Nonce 12 bytes (chuẩn cho AES-GCM)
nonce = os.urandom(12)

# Dữ liệu cảm biến
sensor_data = "Temperature=31.5°C, Humidity=72%"

# Chuyển sang bytes
plaintext = sensor_data.encode()

# Mã hóa
ciphertext = aesgcm.encrypt(nonce, plaintext, None)

print("\n[4] Sensor Data Encrypted")

print("Original Data:")
print(sensor_data)

print("\nCiphertext (Hex):")
print(ciphertext.hex())

# =========================
# Decrypt Sensor Data
# =========================

decrypted = aesgcm.decrypt(nonce, ciphertext, None)

print("\n[5] Sensor Data Decrypted")

print(decrypted.decode())