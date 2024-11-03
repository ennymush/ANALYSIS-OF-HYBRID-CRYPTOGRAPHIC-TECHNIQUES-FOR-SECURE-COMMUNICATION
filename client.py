import socket
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC, SHA256
import threading
import getpass

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

def discover_server():
    # Set up the discovery socket
    discovery_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    discovery_socket.settimeout(5)
    discovery_socket.sendto(b"DISCOVER_SERVER", ('<broadcast>', 9999))
    
    try:
        message, addr = discovery_socket.recvfrom(1024)
        if message.decode() == "SERVER_FOUND":
            return addr[0]  # Return server IP address
    except socket.timeout:
        print("Server discovery timed out.")
        return None

def handle_server(connection, aes_key):
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
            print("Server:", decrypted_data.decode())

        except (ConnectionResetError, ConnectionAbortedError, ValueError) as e:
            print(f"Server disconnected or integrity check failed: {e}")
            break

def client_chat():
    server_ip = discover_server()
    if not server_ip:
        return
    
    print(f"Discovered server at IP: {server_ip}")

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_ip, 12345))
    
    # Receive the public key from the server
    public_key = client_socket.recv(2048)  # Adjust size as needed
    rsa_public_key = RSA.import_key(public_key)

    # Generate AES key
    aes_key = get_random_bytes(16)

    # Encrypt the AES key with the server's public key
    encrypted_aes_key = encrypt_aes_key(aes_key, rsa_public_key.export_key())
    
    # Send the encrypted AES key to the server
    client_socket.send(encrypted_aes_key)
    
    # Prompt user for passkey
    passkey = getpass.getpass("Enter passkey for AES key derivation: ").encode()
    
    # Derive AES key from passkey
    salt = b'secure_salt'  # Use a secure and unique salt in production
    derived_aes_key = derive_aes_key(passkey, salt)

    def send_messages():
        while True:
            message = input("You: ").encode()
            if message.lower() == b'exit':
                print("Ending chat.")
                break

            nonce, ciphertext, tag, hmac = encrypt_data(message, derived_aes_key)
            
            # Send nonce
            client_socket.send(nonce)
            
            # Send ciphertext length and then ciphertext
            client_socket.send(len(ciphertext).to_bytes(4, byteorder='big'))
            client_socket.send(ciphertext)
            
            # Send tag
            client_socket.send(tag)
            
            # Send HMAC
            client_socket.send(hmac)

        client_socket.close()

    # Start threads for receiving messages and sending messages
    threading.Thread(target=handle_server, args=(client_socket, derived_aes_key)).start()
    send_messages()

if __name__ == "__main__":
    client_chat()
 