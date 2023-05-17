from socket import create_connection
from ssl import SSLContext, PROTOCOL_TLS_CLIENT
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import threading
import comm
import sys
import dhl
from OpenSSL import crypto
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

hostname='example.org'
ip = '127.0.0.1'
port = 8443
context = SSLContext(PROTOCOL_TLS_CLIENT)
context.load_verify_locations('cert.pem')

global comm_context
comm_context = {}

#get server public key
with open("cert.pem", "rb") as key_file:
    cert = key_file.read()

crtObj = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
pubKeyObject = crtObj.get_pubkey()
pubKeyString = crypto.dump_publickey(crypto.FILETYPE_PEM,pubKeyObject)

server_public_key = serialization.load_pem_public_key(
        pubKeyString,
    )

server_public_pem = server_public_key.public_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PublicFormat.SubjectPublicKeyInfo
)
#
# get client2 private key
with open("client2_private_key.pem", "rb") as key_file:
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
#get client2 public key
with open("client2_public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
    )

public_pem = public_key.public_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PublicFormat.SubjectPublicKeyInfo
)
#

with create_connection((ip, port)) as client:
    with context.wrap_socket(client, server_hostname=hostname) as tls:
        comm_context["id"] = int(tls.recv(1024))
        print(comm_context['id'])
        print(f'Using {tls.version()}\n')
        tls.sendall(input("Username: ").encode())
        tls.sendall(input("Password: ").encode())
        tls.sendall(public_pem)
        while True:
            data = tls.recv(1024)
            parsed_data = comm.encoded_json_to_obj(data)
            print(parsed_data)
            message = input("Enter message to send: ")
            tls.sendall(comm.message(message, 1, comm_context))
            if message == "diffie-hellman ack":
                break

        skey, nonce = dhl.recv(tls, 1, comm_context)
        while True:
            data = tls.recv(2048)
            print(data)
            text = comm.encoded_json_to_obj(data)["message"]
            if text == "chat with group":
                break
            print("Chat from 1: " + comm.sym_decrypt(text, skey, nonce))
            tls.sendall(comm.message(comm.sym_encrypt(input("Chat: ").encode(), skey, nonce), 1, comm_context))

        while True:
            #recv message1
            data = tls.recv(1024)
            print(data)
            text = comm.encoded_json_to_obj(data)["message"]
            print("Chat from 1: " + comm.sym_decrypt(text, skey, nonce))
            #send message2 
            message = input("Chat: ")
            enc_message = comm.sym_encrypt(message.encode(), skey, nonce)
            tls.sendall(comm.message(enc_message, 0, comm_context))
            #recv message3
            data = tls.recv(1024)
            print(data)
            text = comm.encoded_json_to_obj(data)["message"]
            print("Chat from 3: " + comm.sym_decrypt(text, skey, nonce))   