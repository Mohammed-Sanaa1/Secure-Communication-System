import socket
import threading

def handle_client(client_socket, client_address, clients):
    print(f"Connection from {client_address} has been established.")
    public_key = client_socket.recv(4096)
    print(f"Received public key from {client_address}")

    # Store the client's socket and public key
    clients[client_address] = (client_socket, public_key)

    # Wait until we have two clients connected
    while len(clients) < 2:
        pass

    # Get the other client's address
    other_client_address = next(addr for addr in clients if addr != client_address)

    # Send the other client's public key to this client
    client_socket.send(clients[other_client_address][1])

    print(f"Sent public key to {client_address}")
    client_socket.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 9999))
    server.listen(5)
    print("Server is listening on port 9999")

    clients = {}

    while True:
        client_socket, client_address = server.accept()
        client_handler = threading.Thread(target=handle_client, args=(client_socket, client_address, clients))
        client_handler.start()

if __name__ == "__main__":
    start_server()
