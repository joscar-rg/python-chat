from utils import *
import random
import socket
import struct
import threading
import uuid
import json
import tkinter as tk
from tkinter import ttk
from datetime import datetime

# Multicast configuration
MULTICAST_GROUP = '224.1.1.1'  # TODO: Generate the last octet randomly
MULTICAST_PORT = 5006  # Generate the port randomly

class Server:
    def __init__(self):
        self.clients = {}  # Registered clients
        self.lock = threading.Lock()  # Thread-safe lock
        self.groups = []  # Multicast groups

        # Create TCP socket
        self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp_socket.bind((TCP_IP, TCP_PORT))
        self.tcp_socket.listen()

        # Create multicast socket
        self.multicast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.multicast_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

        # Initialize GUI
        self.root = tk.Tk()
        self.root.title("Server Log")
        self.setup_gui()

    def setup_gui(self):
        """Set up the server GUI."""
        frame = tk.Frame(self.root)
        frame.pack(padx=10, pady=10)

        self.log = tk.Listbox(frame, width=90, height=30)
        self.log.pack(side=tk.LEFT, fill=tk.BOTH)

        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.log.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.log.config(yscrollcommand=scrollbar.set)
        self.log_message("Server started and waiting for incoming connections...")

    def log_message(self, message):
        self.log.insert(tk.END, f"INFO - {datetime.now()} - {message}")

    def handle_client(self, conn, addr):
        """Handle a client connection."""
        _id = str(uuid.uuid4())
        conn.sendall(f"ID:{_id}".encode())

        nickname = conn.recv(BUFFER_SIZE).decode()
        with self.lock:
            self.clients[_id] = {'nickname': nickname, 'conn': conn}
            self.broadcast_users()

        self.log_message(f"User [{nickname}] has joined from {addr}")

        while True:
            data_encoded = conn.recv(1024)
            if not data_encoded:
                break

            data = data_encoded.decode()
            type, destId, content = data.split(":", 2)

            match type:
                case "MSG":
                    self.forward_unicast_message(_id, destId, content)
                case "FILE":
                    self.forward_unicast_file(_id, destId, content, conn)
                case "GROUP":
                    self.handle_group_message(nickname, destId, content)
                case _:
                    print("Unknown message type")

        conn.close()
        self.log_message(f"User [{nickname}] has left.")

    def forward_unicast_message(self, sender_id, dest_id, content):
        """Forward a message to a client."""
        dest = self.clients[dest_id]
        data = f"MSG:{sender_id}:{content}"
        dest['conn'].sendall(data.encode())
        self.log_message(f"[{self.clients[sender_id]['nickname']}] sent a message to [{dest['nickname']}] - {content}")

    def forward_unicast_file(self, sender_id, dest_id, content, conn):
        """Forward a file to a client."""
        dest = self.clients[dest_id]
        msg_type = f"FILE:{sender_id}:{content}"
        dest['conn'].sendall(msg_type.encode())

        # Receive filename length and filename
        filesize = struct.unpack("!I", conn.recv(4))[0]
        filename = conn.recv(filesize).decode()

        # Forward filename length and filename to the destination client
        dest['conn'].sendall(struct.pack("!I", filesize) + filename.encode())

        # Forward the file data
        remaining = filesize
        while remaining > 0:
            data = conn.recv(min(BUFFER_SIZE, remaining))
            if not data:
                break
            dest['conn'].sendall(data)
            remaining -= len(data)

        self.log_message(f"[{self.clients[sender_id]['nickname']}] sent a file to [{dest['nickname']}] - {content}")
        
    def handle_group_message(self, nickname, user_ids, group_name):
        """Handle a GROUP message from a client."""
        user_ids = user_ids.split(",")

        # Generate a new multicast IP and port
        multicast_ip = f"224.1.1.{random.randint(1, 254)}"
        multicast_port = random.randint(5007, 9999)

        # Create a new UDP socket for the multicast group
        group_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        group_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Bind the socket to the multicast port
        group_socket.bind(('', multicast_port))

        # Join the multicast group
        mreq = socket.inet_aton(multicast_ip) + socket.inet_aton('0.0.0.0')
        group_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        # Store the group information
        group_id = str(uuid.uuid4())
        self.clients[group_id] = {'nickname': group_name, 'conn': group_socket, 'ip': multicast_ip, 'port': multicast_port}

        # Send group information to all participants
        for user_id in user_ids:
            dest = self.clients[user_id]
            message = f"GROUP:{group_id}:{group_name}:{multicast_ip}:{multicast_port}"
            dest['conn'].sendall(message.encode())

        # Start a new thread to receive multicast messages
        threading.Thread(target=self.receive_multicast, args=(group_name, group_socket), daemon=True).start()

        self.log_message(f"[{nickname}] created the group [{group_name}]")
        
    def receive_multicast(self, group_name, multicast_socket):
        """Receive multicast messages from the server."""
        while True:
            encrypted_data = multicast_socket.recv(1024)
            data = decrypt_message(encrypted_data)
            type, content = data.split(":", 1)

            match type:
                case "MSG":
                    _, sender_id, message = content.split(":", 2)
                    self.log_message(f"[{self.clients[sender_id]['nickname']}] sent a group message to [{group_name}] - {message}")
                case "FILE":
                    pass
                case _:
                    print("Unknown message type")

    def broadcast_users(self):
        """Broadcast the list of connected users to all clients."""
        data = {key: value['nickname'] for key, value in self.clients.items()}
        data = f"USERS:{json.dumps(data)}"
        encrypted_data = encrypt_message(data)
        self.multicast_socket.sendto(encrypted_data, (MULTICAST_GROUP, MULTICAST_PORT))

    def start(self):
        """Start the server."""
        threading.Thread(target=self.accept_clients, daemon=True).start()
        self.root.mainloop()

    def accept_clients(self):
        """Accept incoming client connections."""
        while True:
            conn, addr = self.tcp_socket.accept()
            threading.Thread(target=self.handle_client, args=(conn, addr)).start()

if __name__ == "__main__":
    server = Server()
    server.start()