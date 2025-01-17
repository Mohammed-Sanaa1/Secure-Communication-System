import socket
import threading
import random
from sympy import isprime
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
import base64
import struct
import time
# from collections import deque
# Simplified block cipher-like approach (not AES, but for educational purposes)
# class AESCipher:
#     def __init__(self, key):
#         # Simplified key expansion for educational purposes (not AES key schedule)
#         self.key = key

#     def encrypt(self, data):
#         # Just an example using XOR-based encryption for simplicity
#         cipher = deque(data)  # no need to encode, assuming 'data' is already in bytes
#         for i in range(len(cipher)):
#             cipher[i] ^= self.key[i % len(self.key)]  # Simple XOR encryption with key
#         return bytes(cipher)

#     def decrypt(self, data):
#         # Decryption is same as encryption in XOR-based cipher
#         cipher = deque(data)
#         for i in range(len(cipher)):
#             cipher[i] ^= self.key[i % len(self.key)]  # Simple XOR decryption with key
#         # Decode only if the result is a bytes object
#         return bytes(cipher).decode('utf-8')



class AESCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        iv = cipher.iv
        return iv + ct_bytes

    def decrypt(self, data):
        iv = data[:AES.block_size]
        ct = data[AES.block_size:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt
    


# SHA-256 constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes)
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0b5f8,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

# Rotate right function
def rotr(x, n):
    return (x >> n) | (x << (32 - n)) & 0xFFFFFFFF

# SHA-256 Compression function
def sha256(message):
    # Ensure message is a string before processing
    if isinstance(message, bytes):  # If it's already bytes, no need to encode it again
        message = bytearray(message)
    else:  # If it's a string, convert to bytes
        message = bytearray(message, 'utf-8')
    
    length = len(message) * 8  # message length in bits
    message.append(0x80)  # append the bit 1 (0x80 byte)
    
    # Pad the message with zeros until the length is 64 bits short of a multiple of 512
    while (len(message) * 8) % 512 != 448:
        message.append(0x00)

    # Append the length of the original message as a 64-bit integer
    message += struct.pack('>Q', length)

    # Initialize hash values
    h = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]

    # Process each 512-bit chunk of the message
    for i in range(0, len(message), 64):
        chunk = message[i:i+64]
        
        # Break chunk into sixteen 32-bit words
        w = list(struct.unpack('>16I', chunk))  # Unpack 16 32-bit words
        
        # Extend the 16 words into 64 words
        for t in range(16, 64):
            s0 = rotr(w[t-15], 7) ^ rotr(w[t-15], 18) ^ (w[t-15] >> 3)
            s1 = rotr(w[t-2], 17) ^ rotr(w[t-2], 19) ^ (w[t-2] >> 10)
            w.append((w[t-16] + s0 + w[t-7] + s1) & 0xFFFFFFFF)
        
        # Initialize working variables
        a, b, c, d, e, f, g, h_ = h
        
        # Main loop (64 rounds)
        for t in range(64):
            S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (h_ + S1 + ch + K[t] + w[t]) & 0xFFFFFFFF
            S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF
            
            # Update working variables
            h_ = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF
        
        # Add the compressed chunk to the current hash value
        h = [(x + y) & 0xFFFFFFFF for x, y in zip(h, [a, b, c, d, e, f, g, h_])]

    # Return the final hash value as a hexadecimal string
    return ''.join(f'{x:08x}' for x in h)


# RSA encryption function
def encrypt(message, public_key):
    e, n = public_key
    message_int = int.from_bytes(message.encode(), 'big')
    ciphertext = pow(message_int, e, n) #C= M^e mod n
    return ciphertext

# RSA decryption function
def decrypt(ciphertext, private_key):
    d, n = private_key
    decrypted_int = pow(ciphertext, d, n) #M = C^d mod n
    message = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, 'big').decode()
    return message


#FOR RSA
def generate_prime(bits=2048):
    while True:
        num = random.getrandbits(bits)
        if isprime(num):
            return num

def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1

def generate_rsa_keys(bits=2048):
    #each prime number p and q is 2048 bits
    p = generate_prime(bits)
    q = generate_prime(bits)
    n = p * q #n=qp will have approximately 4096 bits
    r = (p - 1) * (q - 1)

    #choosing e
    while True:
        e = random.randint(2, r - 1)
        if gcd(e, r) == 1:
            break

    #calculating d  st.==> ed mod r =1
    d = mod_inverse(e, r)

    return (e, n), (d, n) #(e,n) are public key and d is the private key

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a



# FOR SIGNING AND VERIFICATION (Digital signiture)
def sign_message(message, private_key):
    hash_obj = sha256(message)
    hash_int = int(hash_obj, 16)

    signature = pow(hash_int, private_key[0], private_key[1]) #S = h(M)^d mod n
    return signature

def verify_signature(message, signature, public_key):
    hash_obj = sha256(message)
    hash_int = int(hash_obj, 16)

    decrypted_hash = pow(signature, public_key[0], public_key[1]) #h(M) = S^e mod n

    return hash_int == decrypted_hash # Compare the decrypted hash with the computed hash



#keep sending and receiving mmessages between you and the connected client
def receive_messages(sock, cipher, other_public_key):
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break
            data_str = data.decode('utf-8')

            #splitting the recived concated string
            encrypted_message_str, signature_str = data_str.rsplit('|', 1)

            #return data to there original types before been sent
            encrypted_message = base64.b64decode(encrypted_message_str)
            signature = int(signature_str)

            #decrypting the message and vferifying it
            start_decryption_time = time.time()
            decrypted_message = cipher.decrypt(encrypted_message)
            start_time_verification = time.time()
            if verify_signature(decrypted_message.decode(), signature, other_public_key):
                print(f"Received: {decrypted_message.decode()}\n")
            else:
                print("Message verification failed!")
            end_decryption_time = time.time()
            print(f"verification time: {end_decryption_time - start_time_verification}")
            print(f"Decryption time: {start_time_verification - start_decryption_time}")

        except Exception as e:
            print(f"Error: {e}")
            break

def send_messages(sock, cipher, private_key):
    while True:
        message = input("")

        while len(message) > 2540 or len(message) == 0:
            if len(message) == 0:
                print("The message is emmpty!")
            else:
                print(f"Message is too long, you should delete {len(message)-2540} charecters")
            message = input("")
            
        if message == "exit":
            break

        start_time_signiture = time.time()
        signature = sign_message(message, private_key) #S=h(M)^d mod n
        end_time_signiture = time.time()
        encrypted_message = cipher.encrypt(message.encode()) # aes_enc(M)
        end_time_encryption = time.time()
        print(f"Creating signature time: {end_time_signiture - start_time_signiture}")
        print(f"Encryption message time: {end_time_encryption - end_time_signiture}")
        #we are converting them to string to avoid errors at sending and reciving
        encrypted_message_str = base64.b64encode(encrypted_message).decode('utf-8')
        signature_str = str(signature)

        #concat them in one string to be sent at once (separated by "|")
        message_to_send = encrypted_message_str + '|' + signature_str
        sock.send(message_to_send.encode('utf-8'))


#startup, connecting to server, changing keys with a client...
def client_program():
    public_key, private_key = generate_rsa_keys(bits=1024)


    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.connect(("127.0.0.1", 9999))

    server.send(f"{public_key}".encode())

    other_public_key = eval(server.recv(4096).decode())
    # e,n = other_public_key
    print(f"Received other client's public key: {str(other_public_key)[:5]}...")


    server.close()

    choice = input("Enter 'l' to listen or 'c' to connect: ")
    if choice == 'l':
        peer_listener(other_public_key, private_key)
    else:
        peer_connector(other_public_key, private_key)


#YOU will chose wither you want to be the connector or the listener in client_program()
def peer_listener(other_public_key, private_key):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("0.0.0.0", 9998))
    listener.listen(1)
    print("Waiting for connection...")

    conn, addr = listener.accept()
    print(f"Connected to {addr}")

    #receive encrypted AES key and decrypt it (using RSA private key for dycryption)
    ############################################
    key = conn.recv(4096).decode()
    ciphertext_back = int(key)
    print(f"encrypted_key: {str(ciphertext_back)[:5]}...")
    decrypted_key = decrypt(ciphertext_back, private_key)
    print(f"decrypted_key: {str(decrypted_key)[:5]}...")
    key_back_to_bytes = base64.b64decode(decrypted_key.encode('utf-8'))
    cipher = AESCipher(key_back_to_bytes)
    # print(f"Received key: {key_back_to_bytes}")
    ############################################

    receive_thread = threading.Thread(target=receive_messages, args=(conn, cipher, other_public_key,))
    send_thread = threading.Thread(target=send_messages, args=(conn, cipher, private_key,))
    
    receive_thread.start()
    send_thread.start()
    
    receive_thread.join()
    send_thread.join()
    
    conn.close()

def peer_connector(other_public_key, private_key):
    peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    peer.connect(("127.0.0.1", 9998))

    #send encrypted AES key (using RSA public key for encryption)
    ############################################
    key = os.urandom(16) #AES key must be either 16 or 24 or 32 bytes
    cipher = AESCipher(key) 
    key_string = base64.b64encode(key).decode('utf-8') # Convert bytes to a base64 string

    ciphertext = encrypt(key_string, other_public_key)
    # print(type(ciphertext))
    # print(f"ciphertext: {ciphertext}")
    ciphertext_text = str(ciphertext)
    print(f"ciphertext_text: {ciphertext_text[:5]}...")
    peer.send(ciphertext_text.encode())
    ############################################

    receive_thread = threading.Thread(target=receive_messages, args=(peer, cipher, other_public_key,))
    send_thread = threading.Thread(target=send_messages, args=(peer, cipher, private_key,))
    
    receive_thread.start()
    send_thread.start()
    
    receive_thread.join()
    send_thread.join()
    
    peer.close()


if __name__ == "__main__":
    client_program()
