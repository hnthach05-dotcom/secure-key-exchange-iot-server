from cryptography.hazmat.primitives.asymmetric import ec

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