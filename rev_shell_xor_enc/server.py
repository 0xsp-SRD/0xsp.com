import socket


key = b'\x01\x02\x03\x04\x05\x06\x07\x08' 


def encrypt(data):
    # Convert the data to a byte array
    data_bytes = data.encode('ascii')

    # Encrypt the data using the XOR key
    encrypted_bytes = bytearray()
    for i, b in enumerate(data_bytes):
        encrypted_bytes.append(bytes([b])[0] ^ key[i % len(key)])

    # Return the encrypted data as a bytes object
    return encrypted_bytes

# Decrypt the data using the XOR operator and the key
def decrypt(data):
    # Convert the data to a byte array
    data_bytes = bytearray(data)

    # Decrypt the data using the XOR key
    decrypted_bytes = bytearray()
    for i, b in enumerate(data_bytes):
        decrypted_bytes.append(bytes([b])[0] ^ key[i % len(key)])

    # Return the decrypted data as a bytes object
    return decrypted_bytes

    
HOST = '0.0.0.0'
PORT = 4444

server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_sock.bind((HOST, PORT))


server_sock.listen()


client_sock, client_address = server_sock.accept()
print(f'Connected to {client_address[0]}:{client_address[1]}')


while True:
    # Receive an encrypted message from the client
    encrypted_message = client_sock.recv(1024)
    if not encrypted_message:
        break

    # Decrypt the message
    message = decrypt(encrypted_message).decode("ascii")
    print(f'Received: {message}')

    # Send an encrypted response to the client
    response = input('Enter a Command: ')
    encrypted_response = encrypt(response)
    client_sock.send(encrypted_response)


client_sock.close()
server_sock.close()
