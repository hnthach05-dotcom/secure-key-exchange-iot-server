# server.py
import socket
import json
import threading
import time
import config
import crypto_utils

class TLSServer:
    def __init__(self, log_callback=None, use_static=False, use_attacker=False):
        self.log_callback = log_callback
        self.use_static = use_static
        self.use_attacker = use_attacker

        self.server_socket = None
        self.client_socket = None
        self.running = False
        self.session_key = None

    def _log(self, msg):
        if self.log_callback:
            self.log_callback(msg)
        else:
            print(f"[SERVER] {msg}")

    def start(self):
        """Khởi tạo server, chờ client kết nối và thực hiện handshake."""
        self.running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((config.HOST, config.PORT))
        self.server_socket.listen(1)
        self._log(f"Đang lắng nghe tại {config.HOST}:{config.PORT}")

        # ========== CHỌN KEY CHO SERVER ==========
        if self.use_attacker:
            # Dùng key giả mạo để mô phỏng tấn công MITM
            private_key = crypto_utils.attacker_private_key
            self._log("Sử dụng khóa của kẻ tấn công (giả mạo server)")
        else:
            # Dùng key hợp pháp cố định để xác thực thành công
            private_key = crypto_utils.legitimate_private_key
            self._log("Sử dụng khóa hợp pháp cố định của server")
        
        # Ghi log nếu dùng static key
        if self.use_static:
            self._log("Sử dụng khóa tĩnh (cố định)")
        else:
            self._log("Sử dụng khóa ephemeral (mới mỗi phiên)")
        # ===================================================

        self.private_key = private_key
        self.public_key = private_key.public_key()

        # Chấp nhận kết nối từ client
        self.client_socket, addr = self.server_socket.accept()
        self._log(f"Kết nối từ {addr}")

        # Nhận khóa công khai của client
        client_pub_bytes = self.client_socket.recv(1024)
        if not client_pub_bytes:
            raise ConnectionError("Không nhận được khóa công khai từ client")
        client_pub_key = crypto_utils.deserialize_public_key(client_pub_bytes)
        self._log("Đã nhận khóa công khai của client")

        # Gửi khóa công khai của server
        server_pub_bytes = crypto_utils.get_public_key_bytes(self.public_key)
        self.client_socket.send(server_pub_bytes)
        self._log("Đã gửi khóa công khai của server")

        # Tính Shared Secret
        shared_secret = crypto_utils.compute_shared_secret(self.private_key, client_pub_key)
        self._log("Đã tính Shared Secret (ECDH)")

        # Dẫn xuất Session Key
        self.session_key = crypto_utils.derive_session_key(shared_secret)
        self._log("Đã sinh Session Key (HKDF)")

        self._log("== Handshake hoàn tất ==")

    def receive_data(self):
        """Nhận dữ liệu đã mã hóa từ client và giải mã."""
        if self.client_socket is None:
            raise RuntimeError("Chưa có kết nối")

        # Nhận 4 byte độ dài
        len_bytes = self.client_socket.recv(4)
        if not len_bytes:
            return None
        data_len = int.from_bytes(len_bytes, byteorder='big')

        # Nhận toàn bộ dữ liệu mã hóa
        encrypted_data = b''
        while len(encrypted_data) < data_len:
            chunk = self.client_socket.recv(data_len - len(encrypted_data))
            if not chunk:
                break
            encrypted_data += chunk

        if len(encrypted_data) < config.AES_GCM_NONCE_LENGTH:
            raise ValueError("Dữ liệu nhận được quá ngắn")

        nonce = encrypted_data[:config.AES_GCM_NONCE_LENGTH]
        ciphertext = encrypted_data[config.AES_GCM_NONCE_LENGTH:]

        try:
            plaintext = crypto_utils.decrypt_aes_gcm(self.session_key, nonce, ciphertext)
            self._log("Giải mã thành công, tag xác thực hợp lệ")
            return json.loads(plaintext.decode('utf-8'))
        except Exception as e:
            self._log(f"Giải mã thất bại: {e}")
            raise

    def close(self):
        """Đóng kết nối và giải phóng tài nguyên."""
        if self.client_socket:
            self.client_socket.close()
        if self.server_socket:
            self.server_socket.close()
        self.running = False
        self._log("Server đã đóng")