import ssl
import socket
import threading
import comm
import dhl

global sockets, status, dh, messages
sockets = {}
status = {}
dh = {}
messages = {}

HOST = '127.0.0.1'
PORT = 8443

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('cert.pem', 'key.pem')

global comm_context
comm_context = {
    "id": 0
}

allpassword = { #change
    1 : "asdfg",
    2 : "qwerty"
}


def handle_client(conn, addr, client_id, password):# change
    with conn:
        print(f"Client {client_id} connected from {addr}")
        conn.send(f"{client_id}".encode())
        conn.send(f"{password}".encode()) #change
        if client_id == 1: #change
            if password != allpassword[client_id]: #change
                print("wrong password")#change
            else:
                while True:
                    data = conn.recv(1024)
                    parsed_data = comm.encoded_json_to_obj(data)
                    print(f"Received from client {client_id}: {data.decode()}")
                    message = f"Message received from client {client_id}"
                    print(message)
                    if parsed_data["message"] == "diffie-hellman":
                        status[client_id] = 0
                        status[parsed_data["to"]] = 0
                        dh[client_id] = []
                        dh[client_id].append(conn.recv())
                        dh[client_id].append(conn.recv())
                        dh[client_id].append(conn.recv())
                        dh[client_id].append(conn.recv())
                        sockets[parsed_data["to"]].sendall(data)
                        while status[parsed_data["to"]] == 0:
                            pass
                        conn.sendall(dh[parsed_data["to"]].pop(0))
                        break

                    else:
                        conn.sendall(comm.message(message, parsed_data["from"], comm_context))

                messages[client_id] = []
                status[client_id] = 1
                while status[2] == 0:
                    pass
                while True:
                    status[client_id] = 0
                    data = conn.recv(1024)
                    print(data)
                    messages[client_id].append(data)
                    status[client_id] = 1
                    while messages[client_id] != []:
                        pass
                    while messages[2] == []:
                        pass
                    conn.sendall(messages[2].pop(0))
                

        elif client_id == 2:
            while True:
                data = conn.recv(1024)
                parsed_data = comm.encoded_json_to_obj(data)
                print(f"Received from client {client_id}: {data.decode()}")
                message = f"Message received from client {client_id}"
                print(message)
                if parsed_data["message"] == "diffie-hellman ack":
                    dh[client_id] = []
                    conn.sendall(dh[parsed_data["to"]].pop(0))
                    conn.sendall(dh[parsed_data["to"]].pop(0))
                    conn.sendall(dh[parsed_data["to"]].pop(0))
                    conn.sendall(dh[parsed_data["to"]].pop(0))
                    dh[client_id].append(conn.recv(1024))
                    status[client_id] = 1
                    break

                else:
                    conn.sendall(comm.message(message, parsed_data["from"], comm_context))

            messages[client_id] = []
            status[client_id] = 1
            while status[1] == 0:
                pass
            while True:
                while messages[1] == []:
                    pass
                conn.sendall(messages[1].pop(0))
                data = conn.recv(1024)
                print(data)
                messages[client_id].append(data)
                while messages[client_id] != []:
                    pass
                


with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.bind((HOST, PORT))
    sock.listen(5)
    with context.wrap_socket(sock, server_side=True) as ssock:
        print(f"Server listening on {HOST}:{PORT}")
        client_id = 1
        while True:
            conn, addr = ssock.accept()
            sockets[client_id] = conn
            status[client_id] = True
            t = threading.Thread(target=handle_client, args=(conn, addr, client_id))
            t.start()
            client_id += 1
