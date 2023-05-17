import ssl
import socket
import threading
import comm
import dhl
from OpenSSL import crypto
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

with open("cert.pem", "rb") as key_file:
    cert = key_file.read()
#cert is the encrypted certificate int this format -----BEGIN -----END    
crtObj = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
pubKeyObject = crtObj.get_pubkey()
pubKeyString = crypto.dump_publickey(crypto.FILETYPE_PEM,pubKeyObject)
print(pubKeyString)

global sockets, status, dh, messages, public_keys, nonces, three, global_message, accounts
sockets = {}
status = {}
dh = {}
messages = {}
public_keys = {}
nonces = {}
three = False
global_message = ""
accounts = {
    "1": b"\x0f\xfe\x1a\xbd\x1a\x08!SS\xc23\xd6\xe0\ta>\x95\xee\xc4%82\xa7a\xaf(\xff7\xacZ\x15\x0c",
    "2": b'\xed\xee)\xf8\x82T;\x95f \xb2m\x0e\xe0\xe7\xe9P9\x9b\x1cB"\xf5\xde\x05\xe0d%\xb4\xc9\x95\xe9',
    "3": b"1\x8a\xee?\xed\x8c\x9d\x04\r5\xa7\xfc\x1f\xa7v\xfb1083\xaa-\xe8\x855M\xdf=D\xd8\xfbi"
}

HOST = '127.0.0.1'
PORT = 8443

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('cert.pem', 'key.pem')

global comm_context
comm_context = {
    "id": 0
}

# get client1 private key
with open("key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
    )

private_pem = private_key.private_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PrivateFormat.TraditionalOpenSSL,
   encryption_algorithm=serialization.NoEncryption()
)
#

def handle_client(conn, addr, client_id):
    global global_message
    with conn:
        print(f"Client {client_id} connected from {addr}")
        conn.send(f"{client_id}".encode())
        user = conn.recv(1024).decode()
        password = conn.recv(1024)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(password)
        result = digest.finalize()
        if accounts[user] == result:
            print("")
            print("correct password")
        else:
            print("incorrect password")
            return
        public_keys[client_id] = conn.recv(1024)
        print(public_keys[client_id])
        print("")
        if client_id == 1:
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
                    nonces[client_id] = []
                    #send diffie-hellman params
                    dh[client_id].append(conn.recv())
                    dh[client_id].append(conn.recv())
                    dh[client_id].append(conn.recv())
                    nonce = conn.recv()
                    nonces[client_id].append(nonce)
                    dh[client_id].append(nonce)
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
                parsed_data = comm.encoded_json_to_obj(data)
                print(data)
                if parsed_data["type"] == "command":
                    if parsed_data["command"] == "add user":
                        target = int(comm.encoded_json_to_obj(conn.recv(1024))["command"])
                        sockets[target].sendall(comm.message(f"Invite from {client_id}", target, comm_context))
                        status[target] = 1
                        while status[client_id] == 0:
                            pass
                        conn.sendall(comm.message(public_keys[target].decode('latin1'), client_id, comm_context))
                        conn.sendall(comm.message(private_key.sign(
                            public_keys[target],
                            padding.PSS(
                                mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH
                            ),
                            hashes.SHA256()
                        ).decode('latin1'), client_id, comm_context))
                        data = conn.recv(2048)
                        status[client_id] = 1
                        messages[target].append(data)
                        status[target] = 1
                        break
                            
                else:
                    messages[client_id].append(data)
                    status[client_id] = 1
                    while messages[client_id] != []:
                        pass
                    while messages[2] == []:
                        pass
                    conn.sendall(messages[2].pop(0))

            while True:
                #recv message1
                data = conn.recv(1024)
                parsed_data = comm.encoded_json_to_obj(data)
                print(data)
                messages[client_id].append(data)
                while messages[client_id] != []:
                    pass
                #pop and send message2
                status[client_id] = 0
                while messages[2] == []:
                    pass
                global_message = messages[2].pop(0)
                status[client_id] = 1
                conn.sendall(global_message)
                #wait and send message3
                while status[2] == 1:
                    pass
                while status[2] == 0:
                    pass
                conn.sendall(global_message)

            

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
            is_continue = True
            while True:
                global three
                while messages[1] == []:
                    if three == True:
                        conn.sendall(comm.message("chat with group", 2, comm_context))
                        is_continue = False
                        break
                if is_continue == False:
                    break
                conn.sendall(messages[1].pop(0))
                data = conn.recv(1024)
                print(data)
                messages[client_id].append(data)
                while messages[client_id] != []:
                    pass
            
            while True:
                #wait and send message1
                while status[3] == 1:
                    pass
                while status[3] == 0:
                    pass
                conn.sendall(global_message)
                #recv message2
                data = conn.recv(1024)
                parsed_data = comm.encoded_json_to_obj(data)
                print(data)
                messages[client_id].append(data)
                while messages[client_id] != []:
                    pass
                #pop and send message3
                status[client_id] = 0
                while messages[3] == []:
                    pass
                global_message = messages[3].pop(0)
                status[client_id] = 1
                conn.sendall(global_message)

        elif client_id == 3:
            messages[client_id] = []
            status[client_id] = 0
            while status[client_id] == 0:
                pass
            data = conn.recv(1024)
            parsed_data = comm.encoded_json_to_obj(data)
            if parsed_data["message"] == "accept invite":
                status[client_id] = 0
                status[parsed_data["to"]] = 1
                while status[client_id] == 0:
                    pass
                conn.sendall(messages[client_id].pop(0))
                conn.sendall(nonces[parsed_data["to"]].pop(0))
                three = True
            
            while True:
                #pop and send message1
                status[client_id] = 0
                while messages[1] == []:
                    pass
                global_message = messages[1].pop(0)
                status[client_id] = 1
                conn.sendall(global_message)
                #wait and send message 2
                while status[1] == 1:
                    pass
                while status[1] == 0:
                    pass
                conn.sendall(global_message)
                #recv message 3
                data = conn.recv(1024)
                parsed_data = comm.encoded_json_to_obj(data)
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
            status[client_id] = 1
            t = threading.Thread(target=handle_client, args=(conn, addr, client_id))
            t.start()
            client_id += 1
