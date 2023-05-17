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
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

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

with create_connection((ip, port)) as client:
    with context.wrap_socket(client, server_hostname=hostname) as tls:
        comm_context["id"] = int(tls.recv(1024))
        print(comm_context['id'])
        print(f'Using {tls.version()}\n')
        tls.sendall(input("Username: ").encode())
        tls.sendall(input("Password: ").encode())
        while True:
            data = tls.recv(1024)
            parsed_data = comm.encoded_json_to_obj(data)
            print(parsed_data)
            message = input("Enter message to send: ")
            tls.sendall(comm.message(message, 1, comm_context))
            if message == "confirm device":
                break

        nonce = comm.encoded_json_to_obj(tls.recv(2048))["message"].encode('latin1')
        secret = input("secret: ")
        skey2 = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=None).derive(secret.encode())
        encrypted_skey = tls.recv(2048).decode('latin1')
        decryptor = Cipher(
            algorithms.AES256(skey2),
            modes.CTR(b'0' * 16)
        ).decryptor()
        skey = decryptor.update(encrypted_skey.encode('latin1')) + decryptor.finalize()
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
            #recv message3
            data = tls.recv(1024)
            print(data)
            text = comm.encoded_json_to_obj(data)["message"]
            print("Chat from 3: " + comm.sym_decrypt(text, skey, nonce))  