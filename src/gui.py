# gui.py
import tkinter as tk
from tkinter import scrolledtext, ttk
import threading
import queue
import time
from server import TLSServer
from client import TLSClient
import crypto_utils

class App:
    def __init__(self, root):
        self.root = root
        root.title("IoT TLS Demo - Trao đổi khóa an toàn")

        # Biến trạng thái
        self.server_running = False
        self.client_running = False
        self.stop_event = threading.Event()
        self.log_queue = queue.Queue()

        # Frame điều khiển
        control_frame = ttk.Frame(root)
        control_frame.pack(pady=5)

        # Checkboxes
        self.verify_var = tk.BooleanVar(value=True)
        self.static_var = tk.BooleanVar(value=False)
        self.mitm_var = tk.BooleanVar(value=False)

        ttk.Checkbutton(control_frame, text="Xác thực Server", variable=self.verify_var).grid(row=0, column=0, padx=5)
        ttk.Checkbutton(control_frame, text="Dùng khóa tĩnh (Static Keys)", variable=self.static_var).grid(row=0, column=1, padx=5)
        ttk.Checkbutton(control_frame, text="Giả lập MITM (dùng key giả mạo)", variable=self.mitm_var).grid(row=0, column=2, padx=5)

        # Buttons
        btn_frame = ttk.Frame(root)
        btn_frame.pack(pady=5)

        self.btn_start_server = ttk.Button(btn_frame, text="Khởi động Server", command=self.start_server)
        self.btn_start_server.grid(row=0, column=0, padx=5)

        self.btn_start_client = ttk.Button(btn_frame, text="Khởi động Client", command=self.start_client)
        self.btn_start_client.grid(row=0, column=1, padx=5)

        self.btn_run_demo = ttk.Button(btn_frame, text="Chạy Demo Toàn Bộ", command=self.run_full_demo)
        self.btn_run_demo.grid(row=0, column=2, padx=5)

        self.btn_clear = ttk.Button(btn_frame, text="Xóa Log", command=self.clear_logs)
        self.btn_clear.grid(row=0, column=3, padx=5)

        # Khu vực log
        log_frame = ttk.Frame(root)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        ttk.Label(log_frame, text="Log Server").grid(row=0, column=0, sticky="w")
        ttk.Label(log_frame, text="Log Client").grid(row=0, column=1, sticky="w")

        self.server_log = scrolledtext.ScrolledText(log_frame, width=60, height=20, state='disabled')
        self.server_log.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")

        self.client_log = scrolledtext.ScrolledText(log_frame, width=60, height=20, state='disabled')
        self.client_log.grid(row=1, column=1, padx=5, pady=5, sticky="nsew")

        log_frame.columnconfigure(0, weight=1)
        log_frame.columnconfigure(1, weight=1)
        log_frame.rowconfigure(1, weight=1)

        # Bắt đầu xử lý log từ queue
        self.poll_log_queue()

    def poll_log_queue(self):
        """Định kỳ lấy log từ queue và hiển thị lên giao diện."""
        try:
            while True:
                msg, target = self.log_queue.get_nowait()
                if target == 'server':
                    widget = self.server_log
                else:
                    widget = self.client_log
                widget.config(state='normal')
                widget.insert(tk.END, msg + "\n")
                widget.see(tk.END)
                widget.config(state='disabled')
        except queue.Empty:
            pass
        self.root.after(100, self.poll_log_queue)

    def log_server(self, msg):
        self.log_queue.put((msg, 'server'))

    def log_client(self, msg):
        self.log_queue.put((msg, 'client'))

    def clear_logs(self):
        for w in (self.server_log, self.client_log):
            w.config(state='normal')
            w.delete(1.0, tk.END)
            w.config(state='disabled')

    # --------------------------------------------
    # Các hàm khởi chạy server/client trong thread
    # --------------------------------------------
    def start_server(self):
        if self.server_running:
            return
        self.stop_event.clear()
        self.server_running = True
        self.btn_start_server.config(state='disabled')

        def run():
            try:
                server = TLSServer(
                    log_callback=self.log_server,
                    use_static=self.static_var.get(),
                    use_attacker=self.mitm_var.get()
                )
                server.start()
                # Sau handshake, chờ dữ liệu từ client
                data = server.receive_data()
                if data:
                    self.log_server(f"Nhận dữ liệu cảm biến: {data}")
                server.close()
            except Exception as e:
                self.log_server(f"Lỗi: {e}")
            finally:
                self.server_running = False
                self.btn_start_server.config(state='normal')

        threading.Thread(target=run, daemon=True).start()

    def start_client(self):
        if self.client_running:
            return
        self.client_running = True
        self.btn_start_client.config(state='disabled')

        def run():
            try:
                client = TLSClient(
                    log_callback=self.log_client,
                    verify_server=self.verify_var.get(),
                    use_static=self.static_var.get()
                )
                client.connect()
                # Tạo dữ liệu cảm biến giả và gửi
                sensor_data = crypto_utils.generate_sensor_data()
                client.send_data(sensor_data)
                client.close()
                # Thông báo thành công
                self.log_client("Demo hoàn tất.")
            except Exception as e:
                self.log_client(f"Lỗi: {e}")
            finally:
                self.client_running = False
                self.btn_start_client.config(state='normal')

        threading.Thread(target=run, daemon=True).start()

    def run_full_demo(self):
        # Chạy server trước, sau 1 giây chạy client
        self.start_server()
        # Đợi một chút cho server khởi động
        def delayed_client():
            time.sleep(1.5)
            self.start_client()
        threading.Thread(target=delayed_client, daemon=True).start()