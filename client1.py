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
# get client1 private key
with open("client1_private_key.pem", "rb") as key_file:
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
with open("client1_public_key.pem", "rb") as key_file:
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
            message = input("Enter message to send: ")
            tls.sendall(comm.message(message, 2, comm_context))
            if message == "diffie-hellman":
                break
            data = tls.recv(1024)

        skey, nonce = dhl.send(tls, 2, comm_context)
        while True:
            message = input("Chat: ")
            
            if message == "add user":
                tls.sendall(comm.command(message, comm_context))
                who = input("Who(id): ")
                tls.sendall(comm.command(who, comm_context))
                user3_public_pem = comm.encoded_json_to_obj(tls.recv(2048))["message"].encode('latin1')
                server_signature = comm.encoded_json_to_obj(tls.recv(2048))["message"].encode('latin1')
                server_public_key.verify(
                    server_signature, 
                    user3_public_pem,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                user3_public_key = serialization.load_pem_public_key(
                    user3_public_pem,
                )
                cipher_text = user3_public_key.encrypt(
                    skey,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                print(skey)
                tls.sendall(comm.message(cipher_text.decode('latin1'), 3, comm_context))
                break
            else:
                tls.sendall(comm.message(comm.sym_encrypt(message.encode(), skey, nonce), 2, comm_context))
                data = tls.recv(1024)
                print(data)
                text = comm.encoded_json_to_obj(data)["message"]
                print("Chat from 2: " + comm.sym_decrypt(text, skey, nonce))
        
        while True:
            #send message1
            message = input("Chat: ")
            enc_message = comm.sym_encrypt(message.encode(), skey, nonce)
            tls.sendall(comm.message(enc_message, 0, comm_context))
            #recv message2
            data = tls.recv(1024)
            print(data)
            text = comm.encoded_json_to_obj(data)["message"]
            print("Chat from 2: " + comm.sym_decrypt(text, skey, nonce))
            #recv message3
            data = tls.recv(1024)
            print(data)
            text = comm.encoded_json_to_obj(data)["message"]
            print("Chat from 3: " + comm.sym_decrypt(text, skey, nonce))

        
        