# client.py
import socket
import json
import time
import config
import crypto_utils

class TLSClient:
    def __init__(self, log_callback=None, verify_server=True, use_static=False):
        self.log_callback = log_callback
        self.verify_server = verify_server
        self.use_static = use_static
        self.socket = None
        self.session_key = None

    def _log(self, msg):
        if self.log_callback:
            self.log_callback(msg)
        else:
            print(f"[CLIENT] {msg}")

    def connect(self):
        """Kết nối đến server và thực hiện handshake."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((config.HOST, config.PORT))
        self._log(f"Đã kết nối đến {config.HOST}:{config.PORT}")

        # Sinh hoặc dùng key tĩnh
        if self.use_static:
            private_key = crypto_utils.client_static_private_key
            self._log("Sử dụng khóa tĩnh của client")
        else:
            private_key = crypto_utils.generate_ecdh_keypair()[0]
            self._log("Sinh khóa ephemeral (mới mỗi phiên)")

        public_key = private_key.public_key()

        # Gửi khóa công khai của client
        client_pub_bytes = crypto_utils.get_public_key_bytes(public_key)
        self.socket.send(client_pub_bytes)
        self._log("Đã gửi khóa công khai của client")

        # Nhận khóa công khai của server
        server_pub_bytes = self.socket.recv(1024)
        if not server_pub_bytes:
            raise ConnectionError("Không nhận được khóa công khai từ server")
        server_pub_key = crypto_utils.deserialize_public_key(server_pub_bytes)
        self._log("Đã nhận khóa công khai của server")

        # Xác thực server (nếu bật)
        if self.verify_server:
            fingerprint = crypto_utils.get_public_key_fingerprint(server_pub_key)
            if fingerprint == crypto_utils.LEGITIMATE_FINGERPRINT:
                self._log("Xác thực server THÀNH CÔNG (fingerprint khớp)")
            else:
                self._log("Xác thực server THẤT BẠI (fingerprint không khớp)")
                raise ValueError("Server không hợp lệ!")
        else:
            self._log("Bỏ qua xác thực server (không an toàn)")

        # Tính Shared Secret
        shared_secret = crypto_utils.compute_shared_secret(private_key, server_pub_key)
        self._log("Đã tính Shared Secret (ECDH)")

        # Dẫn xuất Session Key
        self.session_key = crypto_utils.derive_session_key(shared_secret)
        self._log("Đã sinh Session Key (HKDF)")

        self._log("== Handshake hoàn tất ==")

    def send_data(self, data_dict):
        """Mã hóa và gửi dữ liệu JSON đến server."""
        if self.socket is None:
            raise RuntimeError("Chưa kết nối")

        plaintext = json.dumps(data_dict).encode('utf-8')
        nonce, ciphertext = crypto_utils.encrypt_aes_gcm(self.session_key, plaintext)
        encrypted = nonce + ciphertext

        # Gửi độ dài + dữ liệu
        self.socket.send(len(encrypted).to_bytes(4, byteorder='big'))
        self.socket.send(encrypted)
        self._log(f"Đã gửi dữ liệu mã hóa: {data_dict}")

    def close(self):
        if self.socket:
            self.socket.close()
        self._log("Client đã đóng")