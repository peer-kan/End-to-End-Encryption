from socket import create_connection
from ssl import SSLContext, PROTOCOL_TLS_CLIENT
import threading
import comm
import sys
import dhl

hostname='example.org'
ip = '127.0.0.1'
port = 8443
context = SSLContext(PROTOCOL_TLS_CLIENT)
context.load_verify_locations('cert.pem')

global comm_context
comm_context = {}

with create_connection((ip, port)) as client:
    with context.wrap_socket(client, server_hostname=hostname) as tls:  
        comm_context["id"] = int(tls.recv(1024))
        print(comm_context['id'])
        print(f'Using {tls.version()}\n')
        password = input("fill password")# fill password and send it io server
        # condition about password 

        
        while True:
            data = tls.recv(1024)
            parsed_data = comm.encoded_json_to_obj(data)
            print(parsed_data)
            message = input("Enter message to send: ")
            tls.sendall(comm.message(message, 1, comm_context))
            if message == "diffie-hellman ack":
                break

        skey, encryptor, decryptor = dhl.recv(tls, 1, comm_context)
        while True:
            data = tls.recv(1024)
            print(data)
            text = comm.encoded_json_to_obj(data)["message"]
            print(comm.sym_decrypt(text, decryptor))
            tls.sendall(comm.message(comm.sym_encrypt(input("Chat: ").encode(), encryptor), 1, comm_context))