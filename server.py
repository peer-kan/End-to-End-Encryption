import ssl
import socket
import threading

HOST = '127.0.0.1'
PORT = 8443

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('cert.pem', 'key.pem')

def handle_client(conn, addr, client_id):
    with conn:
        print(f"Client {client_id} connected from {addr}")
        while True:
            data = conn.recv(1024)
            if not data:
                break
            print(f"Received from client {client_id}: {data.decode()}")
            conn.sendall(f"Message received from client {client_id}".encode())

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.bind((HOST, PORT))
    sock.listen(5)
    with context.wrap_socket(sock, server_side=True) as ssock:
        print(f"Server listening on {HOST}:{PORT}")
        client_id = 1
        while True:
            conn, addr = ssock.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr, client_id))
            t.start()
            client_id += 1
