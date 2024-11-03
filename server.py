import socket
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC, SHA256
import threading
import getpass

# Generate RSA keys for the server
private_key = RSA.generate(2048)
public_key = private_key.publickey().export_key()

# Derive AES key from passkey using PBKDF2
def derive_aes_key(passkey, salt):
    return PBKDF2(passkey, salt, dkLen=32, count=1000000)

def encrypt_aes_key(aes_key, rsa_public_key):
    rsa_cipher = PKCS1_OAEP.new(RSA.import_key(rsa_public_key))
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)
    return encrypted_aes_key

def decrypt_aes_key(encrypted_aes_key, rsa_private_key):
    rsa_cipher = PKCS1_OAEP.new(RSA.import_key(rsa_private_key))
    aes_key = rsa_cipher.decrypt(encrypted_aes_key)
    return aes_key

def encrypt_data(data, aes_key):
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    hmac = HMAC.new(aes_key, ciphertext, SHA256).digest()
    return cipher_aes.nonce, ciphertext, tag, hmac

def decrypt_data(nonce, ciphertext, tag, hmac, aes_key):
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    # Verify HMAC
    expected_hmac = HMAC.new(aes_key, ciphertext, SHA256).digest()
    if hmac != expected_hmac:
        raise ValueError("Message integrity check failed")
    return decrypted_data

def handle_client(connection, aes_key):
    print("Client connected.")
    while True:
        try:
            # Receive nonce
            nonce = connection.recv(16)  # AES nonce is 16 bytes
            
            # Receive ciphertext length and then ciphertext
            ciphertext_length = int.from_bytes(connection.recv(4), byteorder='big')
            ciphertext = connection.recv(ciphertext_length)
            
            # Receive tag
            tag = connection.recv(16)  # AES tag is 16 bytes
            
            # Receive HMAC
            hmac = connection.recv(32)  # HMAC-SHA256 is 32 bytes
            
            # Decrypt data
            decrypted_data = decrypt_data(nonce, ciphertext, tag, hmac, aes_key)
            print("Client:", decrypted_data.decode())

        except (ConnectionResetError, ConnectionAbortedError, ValueError) as e:
            print(f"Client disconnected or integrity check failed: {e}")
            break

def server_chat(connection, aes_key):
    while True:
        message = input("You: ").encode()
        if message.lower() == b'exit':
            print("Ending chat.")
            break

        nonce, ciphertext, tag, hmac = encrypt_data(message, aes_key)
        
        # Send nonce
        connection.send(nonce)
        
        # Send ciphertext length and then ciphertext
        connection.send(len(ciphertext).to_bytes(4, byteorder='big'))
        connection.send(ciphertext)
        
        # Send tag
        connection.send(tag)
        
        # Send HMAC
        connection.send(hmac)

    connection.close()

def start_server():
    # Set up the discovery socket
    discovery_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    discovery_socket.bind(('', 9999))  # Listen on port 9999 for discovery

    print("Server is broadcasting for discovery...")
    while True:
        message, addr = discovery_socket.recvfrom(1024)
        if message.decode() == "DISCOVER_SERVER":
            discovery_socket.sendto(b"SERVER_FOUND", addr)
            break

    # Set up the communication socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 12345))
    server_socket.listen(5)
    
    print("Server is listening for connections...")

    def client_handler(client_conn):
        # Send the public key to the client
        client_conn.send(public_key)
        
        # Receive the encrypted AES key from the client
        encrypted_aes_key = client_conn.recv(256)  # Adjust size as needed
        aes_key = decrypt_aes_key(encrypted_aes_key, private_key.export_key())
        
        # Prompt user for passkey
        passkey = getpass.getpass("Enter passkey for AES key derivation: ").encode()
        
        # Derive AES key from passkey
        salt = b'secure_salt'  # Use a secure and unique salt in production
        derived_aes_key = derive_aes_key(passkey, salt)
        
        # Handle communication with the client
        threading.Thread(target=handle_client, args=(client_conn, derived_aes_key)).start()
        server_chat(client_conn, derived_aes_key)

    while True:
        client_conn, _ = server_socket.accept()
        threading.Thread(target=client_handler, args=(client_conn,)).start()

if __name__ == "__main__":
    start_server()
