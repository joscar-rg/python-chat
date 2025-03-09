from utils import *
import socket
import struct
import threading
import json
import tkinter as tk
from tkinter import messagebox, filedialog
import os
import webbrowser
import time

# Configuración del servidor TCP
TCP_IP = '127.0.0.1'
#TCP_PORT = 5005

# Configuración del grupo multicast
MULTICAST_GROUP = '224.1.1.1' # TODO: we should get this addr from the server
MULTICAST_PORT = 5006 # TODO: we should get this port from the sever

class Client:
    def __init__(self):
        # Initialize the Tkinter root window first
        self.root = tk.Tk()
        self.root.title("User Message Interface")
        self.root.withdraw()
        
        # Get the user's nickname using a dialog
        self.nickname = get_nickname(self.root)
        if not self.nickname:
            print("No nickname provided. Exiting...")
            self.root.quit()
            return

        # Show the root window after the nickname is entered
        self.root.deiconify()
        # Create the user's folder
        create_user_folder(self.nickname)
        
        # Initialize other attributes
        self.selected_group_conn = None # UDP socket of the selected group
        self.selected_file_path = None
        self.users = {}
        self.user_labels = {}
        self.user_messages = {}
        self.selected_user = tk.StringVar()
        self.USER_ID = None

        # Create TCP socket
        self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_socket.connect((TCP_IP, TCP_PORT))

        # Create multicast socket
        self.multicast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.multicast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.multicast_socket.bind(('', MULTICAST_PORT))

        # Join multicast group
        mreq = socket.inet_aton(MULTICAST_GROUP) + socket.inet_aton('0.0.0.0')
        self.multicast_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        # Initialize GUI
        self.setup_gui()

        # Start receiving threads
        threading.Thread(target=self.receive_tcp, daemon=True).start()
        threading.Thread(target=self.receive_multicast, args=(self.multicast_socket,), daemon=True).start()

        # Send nickname to server
        self.tcp_socket.sendall(self.nickname.encode())
        self.root.title(f"User {self.nickname}")

    def setup_gui(self):
        """Set up the client GUI."""
        # Add a dropdown menu
        self.menu_bar = tk.Menu(self.root)
        self.root.config(menu=self.menu_bar)
        
        # Add "Group" menu
        self.group_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Menu", menu=self.group_menu)
        self.group_menu.add_command(label="Create New Group", command=self.create_group)
        
        # Left Frame: User Selection
        self.left_frame = tk.Frame(self.root)
        self.left_frame.pack(side=tk.LEFT, padx=10, pady=10)

        # Right Frame: Message Display and Entry
        right_frame = tk.Frame(self.root)
        right_frame.pack(side=tk.RIGHT, padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Listbox for messages
        self.listbox = tk.Listbox(right_frame, width=50, height=15, state=tk.DISABLED)
        self.listbox.pack(fill=tk.BOTH, expand=True)
        self.listbox.bind("<Double-Button-1>", self.open_file)

        # Entry and Buttons
        entry_frame = tk.Frame(right_frame)
        entry_frame.pack(pady=5)

        self.file_button = tk.Button(entry_frame, text="📁", command=self.pick_file, state=tk.DISABLED)
        self.file_button.pack(side=tk.LEFT, padx=5)

        self.entry = tk.Entry(entry_frame, width=40, state=tk.DISABLED)
        self.entry.pack(side=tk.LEFT, padx=5)

        self.emoji_button = tk.Button(entry_frame, text="😀", command=self.open_emoji_picker, state=tk.DISABLED)
        self.emoji_button.pack(side=tk.LEFT, padx=5)

        self.send_button = tk.Button(entry_frame, text="Send", command=self.send_message, state=tk.DISABLED)
        self.send_button.pack(side=tk.LEFT)

    def format_message(self, origin_id, message):
        timestamp = time.strftime("%H:%M")
        nickname = "You" if origin_id == self.USER_ID else self.users[origin_id]
        formatted_message = f"{nickname} [{timestamp}]: {message}"
        
        return formatted_message

    def send_message(self):
        """Send a message or file to the selected user."""
        message = self.entry.get().strip()
        if not message and not self.selected_file_path:
            messagebox.showwarning("Empty Message", "Please enter a message.")
            return

        selected_user_id = self.selected_user.get()
        if not selected_user_id:
            messagebox.showwarning("No Selection", "Please select a user.")
            return

        if self.selected_file_path:
            self.send_file(selected_user_id, message)
        elif message:
            if self.selected_group_conn:
                data = f"MSG:{selected_user_id}:{self.USER_ID}:{message}"
                encrypted_data = encrypt_message(data)
                group_ip_addr = (self.selected_group_conn['ip'], self.selected_group_conn['port'])
                self.selected_group_conn['socket'].sendto(encrypted_data, group_ip_addr)
            else:
                self.tcp_socket.sendall(f"MSG:{selected_user_id}:{message}".encode())

        formatted_message = self.format_message(self.USER_ID, message)
        self.user_messages[selected_user_id].append(formatted_message)
        self.listbox.insert(tk.END, formatted_message)
        self.entry.delete(0, tk.END)
        self.clear_file_selection()

    def send_file(self, dest_id, message):
        """Send a file to the selected user."""
        filename = os.path.basename(self.selected_file_path).encode("utf-8")
        filesize = os.path.getsize(self.selected_file_path)

        # Send file metadata
        self.tcp_socket.sendall(f"FILE:{dest_id}:{message}".encode())
        self.tcp_socket.sendall(struct.pack("!I", filesize) + filename)

        # Send file data
        with open(self.selected_file_path, "rb") as f:
            while True:
                data = f.read(BUFFER_SIZE)
                if not data:
                    break
                self.tcp_socket.sendall(data)

        print(f"✅ File '{filename.decode()}' sent successfully!")

    def handle_message(self, content):
        origin_id, message = content.split(":", 1)
        formatted_message = self.format_message(origin_id, message)
        self.user_messages[origin_id].append(formatted_message) # TODO here goes the template
        if origin_id == self.selected_user.get():
            self.listbox.insert(tk.END, formatted_message) # TODO here goes the template
        else:
            self.notify_new_message(origin_id)

    def handle_file(self, content):
        origin_id, message = content.split(":", 1)

        # Receive file size and name
        filesize = struct.unpack("!I", self.tcp_socket.recv(4))[0]
        filename = self.tcp_socket.recv(filesize).decode()
        
        # Save the file in the user's folder
        user_folder = os.path.join(os.getcwd(), self.nickname)
        file_path = os.path.join(user_folder, filename)

        # Ensure the user's folder exists
        if not os.path.exists(user_folder):
            os.makedirs(user_folder)

        # Receive file data
        with open(file_path, "wb") as f:
            remaining = filesize
            while remaining > 0:
                data = self.tcp_socket.recv(min(BUFFER_SIZE, remaining))
                if not data:
                    break
                f.write(data)
                remaining -= len(data)

        formatted_message = self.format_message(origin_id, message)
        self.user_messages[origin_id].append(formatted_message) # TODO here goes the template
        if origin_id == self.selected_user.get():
            self.listbox.insert(tk.END, formatted_message) # TODO here goes the template
        else:
            self.notify_new_message(origin_id)

    def handle_group_message(self, content):
        """Handle a GROUP message from the server."""
        group_id, group_name, multicast_ip, multicast_port = content.split(":")
        multicast_port = int(multicast_port)

        # Create a new UDP socket for the multicast group
        group_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        group_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        group_socket.bind(('', multicast_port))

        # Join multicast group
        mreq = socket.inet_aton(multicast_ip) + socket.inet_aton('0.0.0.0')
        group_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        
        # Start a new thread to receive multicast messages
        threading.Thread(target=self.receive_multicast, args=(group_socket,), daemon=True).start()

        # Add a button for the group
        conn = {
            'socket': group_socket,
            'ip': multicast_ip,
            'port': multicast_port
        }
        label = tk.Label(self.left_frame, text=group_name, width=10, relief=tk.RAISED, padx=5, pady=2)
        label.bind("<Button-1>", lambda event, uid=group_id: self.select_user(uid, conn))
        label.pack(anchor=tk.W, pady=2)
        self.user_labels[group_id] = label
        self.user_messages[group_id] = []

    def notify_new_message(self, _id):
        self.user_labels[_id].config(bg="lightblue", fg="white")

    def receive_tcp(self):
        """Receive TCP messages from the server."""
        while True:
            bytes_data = self.tcp_socket.recv(1024)
            print(f"TCP message received => {bytes_data}")
            data = bytes_data.decode()
            type, content = data.split(":", 1)

            match type:
                case "ID":
                    self.USER_ID = content
                case "MSG":
                    self.handle_message(content)
                case "FILE":
                    self.handle_file(content)
                case "GROUP":
                    self.handle_group_message(content)

    def receive_multicast(self, multicast_socket):
        """Receive multicast messages from the server."""
        while True:
            encrypted_data = multicast_socket.recv(1024)
            data = decrypt_message(encrypted_data)
            print(f"Receiving MULTICAST ==> {data}")
            type, content = data.split(":", 1)

            match type:
                case "USERS":
                    self.users = {k: v for k, v in json.loads(content).items() if k != self.USER_ID}
                    self.add_users()
                case "MSG":
                    group_id, sender_id, message = content.split(":", 2)
                    if sender_id != self.USER_ID:
                        formatted_message = self.format_message(sender_id, message)
                        self.user_messages[group_id].append(formatted_message)
                        if group_id == self.selected_user.get():
                            self.listbox.insert(tk.END, formatted_message)
                        else:
                            self.notify_new_message(group_id)

    def add_users(self):
        """Add users to the GUI."""
        user_label_keys = self.user_labels.keys()
        for user_id, username in self.users.items():
            if user_id not in user_label_keys:
                label = tk.Label(self.left_frame, text=username, width=10, relief=tk.RAISED, padx=5, pady=2)
                label.bind("<Button-1>", lambda event, uid=user_id: self.select_user(uid))
                label.pack(anchor=tk.W, pady=2)
                self.user_labels[user_id] = label
                self.user_messages[user_id] = []

    def create_group(self):
        """Open a popup to create a new group."""
        # Create a new window for group creation
        self.group_window = tk.Toplevel(self.root)
        self.group_window.title("Create Group")

        # Label and entry for group name
        tk.Label(self.group_window, text="Group Name (min 5 characters):").pack(padx=10, pady=5)
        self.group_name_entry = tk.Entry(self.group_window, width=30)
        self.group_name_entry.pack(padx=10, pady=5)

        # Bind the group name entry to validate input
        self.group_name_entry.bind("<KeyRelease>", self.validate_group_creation)

        # Label and multi-select dropdown for users
        tk.Label(self.group_window, text="Select Users (min 2):").pack(padx=10, pady=5)
        self.user_listbox = tk.Listbox(self.group_window, selectmode=tk.MULTIPLE, height=5)
        for user_id, username in self.users.items():
            self.user_listbox.insert(tk.END, username)
        self.user_listbox.pack(padx=10, pady=5)

        # Bind the user selection to validate input
        self.user_listbox.bind("<<ListboxSelect>>", self.validate_group_creation)
        
        entry_frame = tk.Frame(self.group_window)
        entry_frame.pack(pady=5)

        # OK button (initially disabled)
        self.ok_button = tk.Button(entry_frame, text="OK", state=tk.DISABLED, command=self.send_group_request)
        self.ok_button.pack(side=tk.LEFT, padx=5)

        # Cancel button
        tk.Button(entry_frame, text="Cancel", command=self.group_window.destroy).pack(side=tk.LEFT)

    def validate_group_creation(self, event=None):
        """Enable the OK button if the group name is valid and at least 2 users are selected."""
        group_name = self.group_name_entry.get().strip()
        selected_users = self.user_listbox.curselection()

        # Enable OK button if conditions are met
        if len(group_name) >= 5 and len(selected_users) >= 2:
            self.ok_button.config(state=tk.NORMAL)
        else:
            self.ok_button.config(state=tk.DISABLED)

    def send_group_request(self):
        """Send a GROUP message to the server."""
        group_name = self.group_name_entry.get().strip()
        selected_users = self.user_listbox.curselection()
        user_ids = [list(self.users.keys())[i] for i in selected_users]
        user_ids.append(self.USER_ID)

        # Send the group creation request to the server
        message = f"GROUP:{','.join(user_ids)}:{group_name}"
        self.tcp_socket.sendall(message.encode())

        # Close the group creation window
        self.group_window.destroy()

    def select_user(self, user_id, conn=None):
        """Select a user to chat with."""
        self.selected_group_conn = conn
        
        # Deselect all users
        for uid, label in self.user_labels.items():
            label.config(bg="lightgray", fg="black")  # Reset appearance
        
        # Select the clicked user
        self.selected_user.set(user_id)
        self.user_labels[user_id].config(bg="green", fg="white")
        
        # Enable the listbox, entry, send button, and emoji button
        self.group_menu.children
        self.listbox.config(state=tk.NORMAL)
        self.entry.config(state=tk.NORMAL)
        self.send_button.config(state=tk.NORMAL)
        self.emoji_button.config(state=tk.NORMAL)
        self.file_button.config(state=tk.NORMAL)
        
        # Clear the listbox and load messages for the selected user
        self.listbox.delete(0, tk.END)
        for message in self.user_messages[user_id]:
            self.listbox.insert(tk.END, message)

    def open_file(self, event):
        """Open a file from the listbox."""
        selected_index = self.listbox.curselection()
        if not selected_index:
            return

        selected_item = self.listbox.get(selected_index)
        if "📄" in selected_item:
            file_name = selected_item.split("📄 ")[-1]
            file_path = os.path.join(self.nickname, file_name)
            if os.path.exists(file_path):
                webbrowser.open(file_path)
            else:
                messagebox.showerror("File Not Found", f"The file '{file_name}' does not exist.")

    def pick_file(self):
        """Pick a file to send."""
        self.selected_file_path = filedialog.askopenfilename(
            title="Select a file",
            filetypes=[("All Files", "*.*"), ("Text Files", "*.txt"), ("Images", "*.jpg *.png")]
        )
        if self.selected_file_path:
            file_name = os.path.basename(self.selected_file_path)
            self.entry.delete(0, tk.END)
            self.entry.insert(tk.END, f"📄 {file_name}")

    def clear_file_selection(self):
        """Clear the selected file."""
        self.selected_file_path = None
        self.entry.delete(0, tk.END)

    def open_emoji_picker(self):
        """Open the emoji picker."""
        emoji_window = tk.Toplevel(self.root)
        emoji_window.title("Emoji Picker")
        emojis = ["😀", "😃", "😄", "😁", "😆", "😅", "😂", "🤣", "😊", "😇"]
        for i in range(0, len(emojis), 10):
            row_frame = tk.Frame(emoji_window)
            row_frame.pack()
            for emoji in emojis[i:i + 10]:
                btn = tk.Button(row_frame, text=emoji, font=("Arial", 8),
                                command=lambda e=emoji: self.entry.insert(tk.END, e))
                btn.pack(side=tk.LEFT)

    def start(self):
        """Start the client."""
        self.root.mainloop()

if __name__ == "__main__":
    client = Client()
    client.start()