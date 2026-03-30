import argparse
import datetime
import json
import queue
import socket
import struct
import threading
import tkinter as tk
from dataclasses import dataclass
from tkinter import ttk

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def encrypt_message(key: bytes, message: str) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode("utf-8"), AES.block_size))
    return cipher.iv + ciphertext


def decrypt_message(key: bytes, encrypted_message: bytes) -> str:
    iv = encrypted_message[: AES.block_size]
    ciphertext = encrypted_message[AES.block_size :]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_message.decode("utf-8")


def recv_exact(sock: socket.socket, size: int) -> bytes:
    buffer = b""
    while len(buffer) < size:
        chunk = sock.recv(size - len(buffer))
        if not chunk:
            raise ConnectionError("Socket closed while receiving data.")
        buffer += chunk
    return buffer


def send_packet(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def recv_packet(sock: socket.socket) -> bytes:
    header = recv_exact(sock, 4)
    length = struct.unpack("!I", header)[0]
    return recv_exact(sock, length)


@dataclass
class ClientSession:
    sock: socket.socket
    address: tuple[str, int]
    aes_key: bytes
    nickname: str = "Anonymous"


class SecureChatServer:
    def __init__(self, logger=None, clients_changed=None):
        self.logger = logger or (lambda msg: print(msg))
        self.clients_changed = clients_changed or (lambda sessions: None)
        self.server_key = RSA.generate(2048)
        self.server_socket = None
        self.clients: dict[socket.socket, ClientSession] = {}
        self.lock = threading.Lock()
        self.running = False

    def log(self, message: str) -> None:
        now = datetime.datetime.now().strftime("%H:%M:%S")
        self.logger(f"[{now}] {message}")

    def start(self, host: str, port: int) -> None:
        if self.running:
            return

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((host, port))
        self.server_socket.listen(10)
        self.server_socket.settimeout(1.0)

        self.running = True
        threading.Thread(target=self._accept_loop, daemon=True).start()
        self.log(f"Server started at {host}:{port}")

    def stop(self) -> None:
        if not self.running:
            return
        self.running = False

        if self.server_socket is not None:
            try:
                self.server_socket.close()
            except OSError:
                pass
            self.server_socket = None

        with self.lock:
            sessions = list(self.clients.values())
            self.clients.clear()

        for session in sessions:
            try:
                session.sock.close()
            except OSError:
                pass

        self.clients_changed([])
        self.log("Server stopped.")

    def _accept_loop(self) -> None:
        while self.running and self.server_socket is not None:
            try:
                client_socket, client_address = self.server_socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            threading.Thread(
                target=self._handle_client,
                args=(client_socket, client_address),
                daemon=True,
            ).start()

    def _safe_remove_client(self, client_socket: socket.socket) -> None:
        with self.lock:
            session = self.clients.pop(client_socket, None)
            sessions = list(self.clients.values())

        if session:
            self.log(f"{session.nickname} disconnected ({session.address[0]}:{session.address[1]}).")
        self.clients_changed(sessions)

        try:
            client_socket.close()
        except OSError:
            pass

    def _handle_client(self, client_socket: socket.socket, client_address: tuple[str, int]) -> None:
        try:
            send_packet(client_socket, self.server_key.publickey().export_key(format="PEM"))
            client_public_key = RSA.import_key(recv_packet(client_socket))

            aes_key = get_random_bytes(16)
            encrypted_aes_key = PKCS1_OAEP.new(client_public_key).encrypt(aes_key)
            send_packet(client_socket, encrypted_aes_key)

            session = ClientSession(sock=client_socket, address=client_address, aes_key=aes_key)

            with self.lock:
                self.clients[client_socket] = session
                sessions = list(self.clients.values())

            self.log(f"Connected: {client_address[0]}:{client_address[1]}")
            self.clients_changed(sessions)

            while self.running:
                encrypted_payload = recv_packet(client_socket)
                plain_payload = decrypt_message(session.aes_key, encrypted_payload)

                try:
                    message_data = json.loads(plain_payload)
                except json.JSONDecodeError:
                    message_data = {"sender": f"{client_address[0]}:{client_address[1]}", "text": plain_payload}

                sender = message_data.get("sender", "Anonymous")
                text = message_data.get("text", "")
                timestamp = message_data.get("timestamp", datetime.datetime.now().strftime("%H:%M:%S"))

                if session.nickname == "Anonymous":
                    session.nickname = sender
                    with self.lock:
                        sessions = list(self.clients.values())
                    self.clients_changed(sessions)

                self.log(f"{sender}: {text}")

                if text.strip().lower() in {"exit", "/exit", "/quit"}:
                    break

                self._broadcast(message_data, exclude=client_socket)

        except (ConnectionError, OSError, ValueError) as exc:
            self.log(f"Connection error with {client_address[0]}:{client_address[1]} ({exc}).")
        finally:
            self._safe_remove_client(client_socket)

    def _broadcast(self, message_data: dict, exclude: socket.socket | None = None) -> None:
        payload = json.dumps(message_data, ensure_ascii=False)
        disconnected: list[socket.socket] = []

        with self.lock:
            sessions = list(self.clients.values())

        for session in sessions:
            if exclude is not None and session.sock == exclude:
                continue
            try:
                encrypted = encrypt_message(session.aes_key, payload)
                send_packet(session.sock, encrypted)
            except OSError:
                disconnected.append(session.sock)

        for sock in disconnected:
            self._safe_remove_client(sock)


class ServerUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AES-RSA Socket Server")
        self.geometry("980x620")
        self.minsize(900, 560)
        self.configure(bg="#0B1220")

        self.event_queue: queue.Queue[tuple[str, object]] = queue.Queue()
        self.server = SecureChatServer(logger=self._queue_log, clients_changed=self._queue_clients)

        self._build_style()
        self._build_layout()
        self.after(100, self._process_queue)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_style(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("App.TFrame", background="#0B1220")
        style.configure("Card.TFrame", background="#111B2E")
        style.configure("Header.TLabel", background="#0B1220", foreground="#E2E8F0", font=("Segoe UI Semibold", 22))
        style.configure("Sub.TLabel", background="#0B1220", foreground="#94A3B8", font=("Segoe UI", 10))
        style.configure("Label.TLabel", background="#111B2E", foreground="#CBD5E1", font=("Segoe UI", 10))
        style.configure("Primary.TButton", background="#2563EB", foreground="white", padding=8, font=("Segoe UI Semibold", 10))
        style.map("Primary.TButton", background=[("active", "#1D4ED8")])
        style.configure("Danger.TButton", background="#DC2626", foreground="white", padding=8, font=("Segoe UI Semibold", 10))
        style.map("Danger.TButton", background=[("active", "#B91C1C")])
        style.configure("Treeview", background="#0F172A", fieldbackground="#0F172A", foreground="#E2E8F0", borderwidth=0, rowheight=28)
        style.configure("Treeview.Heading", background="#1E293B", foreground="#CBD5E1", font=("Segoe UI Semibold", 10))

    def _build_layout(self) -> None:
        root = ttk.Frame(self, style="App.TFrame", padding=18)
        root.pack(fill="both", expand=True)
        root.columnconfigure(0, weight=2)
        root.columnconfigure(1, weight=3)
        root.rowconfigure(2, weight=1)

        header = ttk.Frame(root, style="App.TFrame")
        header.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 14))
        ttk.Label(header, text="AES-RSA Socket Server", style="Header.TLabel").pack(anchor="w")
        ttk.Label(header, text="Secure broadcast chat with per-client AES keys encrypted by RSA.", style="Sub.TLabel").pack(anchor="w")

        control_card = ttk.Frame(root, style="Card.TFrame", padding=14)
        control_card.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 14))
        for i in range(7):
            control_card.columnconfigure(i, weight=0)
        control_card.columnconfigure(7, weight=1)

        ttk.Label(control_card, text="Host", style="Label.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 8))
        self.host_var = tk.StringVar(value="127.0.0.1")
        host_entry = ttk.Entry(control_card, textvariable=self.host_var, width=18)
        host_entry.grid(row=0, column=1, sticky="w", padx=(0, 16))

        ttk.Label(control_card, text="Port", style="Label.TLabel").grid(row=0, column=2, sticky="w", padx=(0, 8))
        self.port_var = tk.StringVar(value="12345")
        port_entry = ttk.Entry(control_card, textvariable=self.port_var, width=10)
        port_entry.grid(row=0, column=3, sticky="w", padx=(0, 16))

        self.status_var = tk.StringVar(value="Stopped")
        status_pill = ttk.Label(control_card, textvariable=self.status_var, style="Label.TLabel")
        status_pill.grid(row=0, column=4, sticky="w", padx=(0, 18))

        self.start_btn = ttk.Button(control_card, text="Start Server", style="Primary.TButton", command=self._start_server)
        self.start_btn.grid(row=0, column=5, sticky="w", padx=(0, 8))

        self.stop_btn = ttk.Button(control_card, text="Stop Server", style="Danger.TButton", command=self._stop_server, state="disabled")
        self.stop_btn.grid(row=0, column=6, sticky="w")

        clients_card = ttk.Frame(root, style="Card.TFrame", padding=12)
        clients_card.grid(row=2, column=0, sticky="nsew", padx=(0, 10))
        clients_card.columnconfigure(0, weight=1)
        clients_card.rowconfigure(1, weight=1)
        ttk.Label(clients_card, text="Connected Clients", style="Label.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 8))

        self.clients_tree = ttk.Treeview(clients_card, columns=("nickname", "address"), show="headings")
        self.clients_tree.heading("nickname", text="Nickname")
        self.clients_tree.heading("address", text="Address")
        self.clients_tree.column("nickname", width=140, anchor="w")
        self.clients_tree.column("address", width=180, anchor="w")
        self.clients_tree.grid(row=1, column=0, sticky="nsew")

        logs_card = ttk.Frame(root, style="Card.TFrame", padding=12)
        logs_card.grid(row=2, column=1, sticky="nsew")
        logs_card.columnconfigure(0, weight=1)
        logs_card.rowconfigure(1, weight=1)
        ttk.Label(logs_card, text="Server Logs", style="Label.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 8))

        self.log_text = tk.Text(
            logs_card,
            bg="#020617",
            fg="#E2E8F0",
            insertbackground="#E2E8F0",
            relief="flat",
            wrap="word",
            font=("Consolas", 10),
        )
        self.log_text.grid(row=1, column=0, sticky="nsew")
        self.log_text.configure(state="disabled")

        log_scroll = ttk.Scrollbar(logs_card, orient="vertical", command=self.log_text.yview)
        log_scroll.grid(row=1, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=log_scroll.set)

    def _queue_log(self, message: str) -> None:
        self.event_queue.put(("log", message))

    def _queue_clients(self, sessions: list[ClientSession]) -> None:
        serialized = [(session.nickname, f"{session.address[0]}:{session.address[1]}") for session in sessions]
        self.event_queue.put(("clients", serialized))

    def _process_queue(self) -> None:
        while not self.event_queue.empty():
            event_type, data = self.event_queue.get()
            if event_type == "log":
                self.log_text.configure(state="normal")
                self.log_text.insert("end", f"{data}\n")
                self.log_text.see("end")
                self.log_text.configure(state="disabled")
            elif event_type == "clients":
                self.clients_tree.delete(*self.clients_tree.get_children())
                for nickname, address in data:
                    self.clients_tree.insert("", "end", values=(nickname, address))

        self.after(100, self._process_queue)

    def _start_server(self) -> None:
        host = self.host_var.get().strip() or "127.0.0.1"
        try:
            port = int(self.port_var.get())
        except ValueError:
            self._queue_log("Invalid port. Please enter a number.")
            return

        try:
            self.server.start(host, port)
        except OSError as exc:
            self._queue_log(f"Cannot start server: {exc}")
            return

        self.status_var.set("Running")
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")

    def _stop_server(self) -> None:
        self.server.stop()
        self.status_var.set("Stopped")
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")

    def _on_close(self) -> None:
        self.server.stop()
        self.destroy()


def run_cli(host: str, port: int) -> None:
    shutdown = threading.Event()
    server = SecureChatServer()
    server.start(host, port)
    print("Type 'exit' and press Enter to stop server.")
    while not shutdown.is_set():
        if input().strip().lower() in {"exit", "/exit", "/quit"}:
            shutdown.set()
    server.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="AES-RSA socket chat server")
    parser.add_argument("--cli", action="store_true", help="Run without graphical UI")
    parser.add_argument("--host", default="127.0.0.1", help="Server host")
    parser.add_argument("--port", type=int, default=12345, help="Server port")
    args = parser.parse_args()

    if args.cli:
        run_cli(args.host, args.port)
        return

    app = ServerUI()
    app.mainloop()


if __name__ == "__main__":
    main()
