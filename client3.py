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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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
# get client1 private key
with open("client3_private_key.pem", "rb") as key_file:
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
#get client1 public key
with open("client3_public_key.pem", "rb") as key_file:
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
        tls.sendall(public_pem)
        while True:
            data = tls.recv(1024)
            parsed_data = comm.encoded_json_to_obj(data)
            print(parsed_data)
            message = input("Enter message to send: ")
            tls.sendall(comm.message(message, 1, comm_context))
            if message == "accept invite":
                break

        encrypted_skey = comm.encoded_json_to_obj(tls.recv(2048))["message"].encode('latin1')
        nonce = comm.encoded_json_to_obj(tls.recv(2048))["message"].encode('latin1')
        skey = private_key.decrypt(
            encrypted_skey, 
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("skey")
        print(skey)
        print("nonce")
        print(nonce)

        while True:
            #recv message1
            data = tls.recv(1024)
            print(data)
            text = comm.encoded_json_to_obj(data)["message"]
            print("Chat from 1: " + comm.sym_decrypt(text, skey, nonce))
            #recv mssage2
            data = tls.recv(1024)
            print(data)
            text = comm.encoded_json_to_obj(data)["message"]
            print("Chat from 2: " + comm.sym_decrypt(text, skey, nonce))
            #send message3
            message = input("Chat: ")
            enc_message = comm.sym_encrypt(message.encode(), skey, nonce)
            print(comm.sym_decrypt(enc_message, skey, nonce))
            tls.sendall(comm.message(enc_message, 0, comm_context))