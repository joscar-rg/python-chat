from tkinter import messagebox, simpledialog
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os
import shutil


# Configuration for the TCP server
TCP_IP = '0.0.0.0'
TCP_PORT = 5005
BUFFER_SIZE = 1024

# Path to the encrypted PEM file
pub_file_path = "certs/pub_key.pem"
# Path to the encrypted PEM file
private_file_path = "certs/private_key.pem"

def get_nickname(root) -> str:
    """Prompt the user for a nickname using a dialog."""
    while True:
        nickname = simpledialog.askstring("Nickname", "Enter your nickname (alphanumeric only):", parent=root)
        if not nickname:
            return None  # User canceled the dialog
        if nickname.isalnum():
            return nickname
        messagebox.showerror("Invalid Nickname", "Nickname must be alphanumeric and non-empty.")
        
def create_user_folder(nickname):
    """Create a folder with the user's nickname. If it exists, remove it first."""
    folder_path = os.path.join(os.getcwd(), nickname)

    # Remove the folder if it already exists
    if os.path.exists(folder_path):
        shutil.rmtree(folder_path)

    # Create a new folder
    os.makedirs(folder_path)
    print(f"Created folder for user: {folder_path}")
        
def encrypt_message(message) -> bytes:
    with open(pub_file_path, "rb") as key_file:

        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

        # Encrypt the message using the public key
        encrypted_message = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
    return encrypted_message

def decrypt_message(encrypted_message) -> str:
    # Load the encrypted private key
    with open(private_file_path, "rb") as key_file:

        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,  # Password to decrypt the key
            backend=default_backend()
        )
        
        print(f"ENCRYPTED MESSAGE ==> {encrypted_message}")
        
        # Decrypt the message using the private key
        message_bytes = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Convert the decrypted bytes back to a string
        return message_bytes.decode()
