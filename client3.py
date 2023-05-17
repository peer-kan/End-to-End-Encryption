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

hostname = 'example.org'
ip = '127.0.0.1'
port = 8443
context = SSLContext(PROTOCOL_TLS_CLIENT)
context.load_verify_locations('cert.pem')

global comm_context
comm_context = {}

# Get server public key
with open("cert.pem", "rb") as key_file:
    cert = key_file.read()

crtObj = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
pubKeyObject = crtObj.get_pubkey()
pubKeyString = crypto.dump_publickey(crypto.FILETYPE_PEM, pubKeyObject)

server_public_key = serialization.load_pem_public_key(pubKeyString)

server_public_pem = server_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Get client private key
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

# Get client public key
with open("client3_public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
    )

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Enter username and password
username = input("Enter username: ")
password = input("Enter password: ")

# Send username and password to the server
auth_data = {
    "username": username,
    "password": password
}
auth_message = comm.message(auth_data, 1, comm_context)
auth_message_json = comm.obj_to_encoded_json(auth_message)
auth_message_encrypted = comm.sym_encrypt(auth_message_json.encode(), server_public_pem, nonce)
auth_message_encrypted_json = comm.obj_to_encoded_json(auth_message_encrypted)

with create_connection((ip, port)) as client:
    with context.wrap_socket(client, server_hostname=hostname) as tls:
        comm_context["id"] = int(tls.recv(1024))
        print(comm_context['id'])
        print(f'Using {tls.version()}\n')
        tls.sendall(public_pem)
        tls.sendall(auth_message_encrypted_json)
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
        print(skey)

        client_thread = dhl.Receive(tls, skey, nonce)
        client_thread.daemon = True
        client_thread.start()

        try:
            while True:
                message = input("Enter message to send: ")
                if message == "quit":
                    sys.exit()
                if message == "end":
                    tls.sendall(comm.message(message, 1, comm_context))
                    sys.exit()
                tls.sendall(comm.message(message, 1, comm_context))
        except KeyboardInterrupt:
            sys.exit()
