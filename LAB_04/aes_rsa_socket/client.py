import argparse
import datetime
import json
import queue
import socket
import struct
import threading
import tkinter as tk
from tkinter import ttk

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
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


class SecureChatClient:
    def __init__(self, on_message=None, on_status=None):
        self.on_message = on_message or (lambda _: None)
        self.on_status = on_status or (lambda _: None)
        self.sock = None
        self.aes_key = None
        self.nickname = "Anonymous"
        self.running = False

    def connect(self, host: str, port: int, nickname: str) -> None:
        if self.running:
            return

        self.nickname = nickname.strip() or "Anonymous"
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))

        client_key = RSA.generate(2048)
        server_public_key = RSA.import_key(recv_packet(self.sock))
        send_packet(self.sock, client_key.publickey().export_key(format="PEM"))

        encrypted_aes_key = recv_packet(self.sock)
        self.aes_key = PKCS1_OAEP.new(client_key).decrypt(encrypted_aes_key)

        self.running = True
        self.on_status(f"Connected to {host}:{port} as {self.nickname}")
        threading.Thread(target=self._receive_loop, daemon=True).start()

        # Introduce nickname to server logs.
        self.send_message("joined the chat")

    def disconnect(self) -> None:
        if not self.running:
            return
        self.running = False

        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

        self.on_status("Disconnected.")

    def send_message(self, text: str) -> None:
        if not self.running or self.sock is None or self.aes_key is None:
            return

        message_data = {
            "sender": self.nickname,
            "text": text,
            "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
        }
        payload = json.dumps(message_data, ensure_ascii=False)
        encrypted = encrypt_message(self.aes_key, payload)
        send_packet(self.sock, encrypted)

    def _receive_loop(self) -> None:
        while self.running and self.sock is not None and self.aes_key is not None:
            try:
                encrypted_payload = recv_packet(self.sock)
                payload = decrypt_message(self.aes_key, encrypted_payload)
                message_data = json.loads(payload)
            except (ConnectionError, OSError, ValueError, json.JSONDecodeError):
                if self.running:
                    self.on_status("Lost connection to server.")
                self.disconnect()
                break
            else:
                self.on_message(message_data)


class ClientUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AES-RSA Socket Client")
        self.geometry("980x620")
        self.minsize(900, 560)
        self.configure(bg="#0B1220")

        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.client = SecureChatClient(on_message=self._queue_message, on_status=self._queue_status)

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
        style.configure("Ghost.TButton", background="#1E293B", foreground="#E2E8F0", padding=8, font=("Segoe UI Semibold", 10))
        style.map("Ghost.TButton", background=[("active", "#334155")])

    def _build_layout(self) -> None:
        root = ttk.Frame(self, style="App.TFrame", padding=18)
        root.pack(fill="both", expand=True)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(2, weight=1)

        header = ttk.Frame(root, style="App.TFrame")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 14))
        ttk.Label(header, text="AES-RSA Secure Chat", style="Header.TLabel").pack(anchor="w")
        ttk.Label(header, text="Messages are encrypted end-to-end between client and server session key.", style="Sub.TLabel").pack(anchor="w")

        conn_card = ttk.Frame(root, style="Card.TFrame", padding=14)
        conn_card.grid(row=1, column=0, sticky="ew", pady=(0, 12))
        for i in range(12):
            conn_card.columnconfigure(i, weight=0)
        conn_card.columnconfigure(11, weight=1)

        ttk.Label(conn_card, text="Host", style="Label.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 8))
        self.host_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(conn_card, textvariable=self.host_var, width=16).grid(row=0, column=1, sticky="w", padx=(0, 14))

        ttk.Label(conn_card, text="Port", style="Label.TLabel").grid(row=0, column=2, sticky="w", padx=(0, 8))
        self.port_var = tk.StringVar(value="12345")
        ttk.Entry(conn_card, textvariable=self.port_var, width=8).grid(row=0, column=3, sticky="w", padx=(0, 14))

        ttk.Label(conn_card, text="Nickname", style="Label.TLabel").grid(row=0, column=4, sticky="w", padx=(0, 8))
        self.nickname_var = tk.StringVar(value="User")
        ttk.Entry(conn_card, textvariable=self.nickname_var, width=16).grid(row=0, column=5, sticky="w", padx=(0, 14))

        self.status_var = tk.StringVar(value="Offline")
        ttk.Label(conn_card, textvariable=self.status_var, style="Label.TLabel").grid(row=0, column=6, sticky="w", padx=(0, 14))

        self.connect_btn = ttk.Button(conn_card, text="Connect", style="Primary.TButton", command=self._connect)
        self.connect_btn.grid(row=0, column=7, padx=(0, 8))

        self.disconnect_btn = ttk.Button(conn_card, text="Disconnect", style="Danger.TButton", command=self._disconnect, state="disabled")
        self.disconnect_btn.grid(row=0, column=8)

        chat_card = ttk.Frame(root, style="Card.TFrame", padding=12)
        chat_card.grid(row=2, column=0, sticky="nsew")
        chat_card.columnconfigure(0, weight=1)
        chat_card.rowconfigure(1, weight=1)

        ttk.Label(chat_card, text="Conversation", style="Label.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 8))
        self.chat_text = tk.Text(
            chat_card,
            bg="#020617",
            fg="#E2E8F0",
            insertbackground="#E2E8F0",
            relief="flat",
            wrap="word",
            font=("Segoe UI", 10),
        )
        self.chat_text.grid(row=1, column=0, sticky="nsew")
        self.chat_text.configure(state="disabled")
        self.chat_text.tag_configure("system", foreground="#22D3EE")
        self.chat_text.tag_configure("self", foreground="#86EFAC")
        self.chat_text.tag_configure("other", foreground="#FDE68A")
        self.chat_text.tag_configure("time", foreground="#64748B")

        scroll = ttk.Scrollbar(chat_card, orient="vertical", command=self.chat_text.yview)
        scroll.grid(row=1, column=1, sticky="ns")
        self.chat_text.configure(yscrollcommand=scroll.set)

        composer = ttk.Frame(chat_card, style="Card.TFrame")
        composer.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        composer.columnconfigure(0, weight=1)
        self.message_var = tk.StringVar()
        self.message_entry = ttk.Entry(composer, textvariable=self.message_var)
        self.message_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.message_entry.bind("<Return>", lambda _: self._send_message())

        self.send_btn = ttk.Button(composer, text="Send", style="Ghost.TButton", command=self._send_message, state="disabled")
        self.send_btn.grid(row=0, column=1)

    def _queue_message(self, message_data: dict) -> None:
        self.events.put(("message", message_data))

    def _queue_status(self, status: str) -> None:
        self.events.put(("status", status))

    def _append_chat(self, sender: str, text: str, timestamp: str, tag: str) -> None:
        self.chat_text.configure(state="normal")
        self.chat_text.insert("end", f"[{timestamp}] ", "time")
        self.chat_text.insert("end", f"{sender}: ", tag)
        self.chat_text.insert("end", f"{text}\n", "other")
        self.chat_text.see("end")
        self.chat_text.configure(state="disabled")

    def _append_system(self, text: str) -> None:
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.chat_text.configure(state="normal")
        self.chat_text.insert("end", f"[{ts}] {text}\n", "system")
        self.chat_text.see("end")
        self.chat_text.configure(state="disabled")

    def _process_queue(self) -> None:
        while not self.events.empty():
            event_type, payload = self.events.get()
            if event_type == "status":
                self.status_var.set(str(payload))
                self._append_system(str(payload))
                if "Connected" in str(payload):
                    self.connect_btn.configure(state="disabled")
                    self.disconnect_btn.configure(state="normal")
                    self.send_btn.configure(state="normal")
                if "Disconnected" in str(payload) or "Lost connection" in str(payload):
                    self.connect_btn.configure(state="normal")
                    self.disconnect_btn.configure(state="disabled")
                    self.send_btn.configure(state="disabled")
            elif event_type == "message":
                sender = str(payload.get("sender", "Anonymous"))
                text = str(payload.get("text", ""))
                timestamp = str(payload.get("timestamp", datetime.datetime.now().strftime("%H:%M:%S")))
                tag = "self" if sender == self.nickname_var.get().strip() else "other"
                self._append_chat(sender, text, timestamp, tag)

        self.after(100, self._process_queue)

    def _connect(self) -> None:
        host = self.host_var.get().strip() or "127.0.0.1"
        nickname = self.nickname_var.get().strip() or "Anonymous"

        try:
            port = int(self.port_var.get())
        except ValueError:
            self._append_system("Port must be a number.")
            return

        try:
            self.client.connect(host, port, nickname)
        except OSError as exc:
            self._append_system(f"Cannot connect to server: {exc}")

    def _disconnect(self) -> None:
        self.client.send_message("/exit")
        self.client.disconnect()

    def _send_message(self) -> None:
        message = self.message_var.get().strip()
        if not message:
            return
        self.client.send_message(message)
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self._append_chat(self.nickname_var.get().strip() or "Me", message, timestamp, "self")
        self.message_var.set("")

    def _on_close(self) -> None:
        self.client.disconnect()
        self.destroy()


def run_cli(host: str, port: int, nickname: str) -> None:
    def print_message(message_data: dict) -> None:
        print(f"[{message_data.get('timestamp', '')}] {message_data.get('sender', 'Anonymous')}: {message_data.get('text', '')}")

    client = SecureChatClient(on_message=print_message, on_status=print)
    client.connect(host, port, nickname)

    print("Type 'exit' to disconnect.")
    while True:
        text = input("> ").strip()
        if not text:
            continue
        if text.lower() in {"exit", "/exit", "/quit"}:
            client.send_message("/exit")
            break
        client.send_message(text)
    client.disconnect()


def main() -> None:
    parser = argparse.ArgumentParser(description="AES-RSA socket chat client")
    parser.add_argument("--cli", action="store_true", help="Run without graphical UI")
    parser.add_argument("--host", default="127.0.0.1", help="Server host")
    parser.add_argument("--port", type=int, default=12345, help="Server port")
    parser.add_argument("--nickname", default="User", help="Display name in chat")
    args = parser.parse_args()

    if args.cli:
        run_cli(args.host, args.port, args.nickname)
        return

    app = ClientUI()
    app.mainloop()


if __name__ == "__main__":
    main()
