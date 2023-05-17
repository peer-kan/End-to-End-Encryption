import comm
from socket import *
import threading
import sys
from OpenSSL import crypto
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

global skey
skey = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

with open("private_key.pem", "wb") as key_file:
    key_file.write(
        skey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

with open("public_key.pem", "wb") as key_file:
    key_file.write(
        skey.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

global cert
cert = crypto.X509()
cert.set_version(0x2)
cert.set_serial_number(0)
cert.get_subject().CN = "localhost"
cert.gmtime_adj_notBefore(0)
cert.gmtime_adj_notAfter(315360000)
cert.set_issuer(cert.get_subject())
cert.set_pubkey(skey.public_key())
cert.sign(skey, "sha256")

with open("cert.pem", "wb") as cert_file:
    cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

tls = socket(AF_INET, SOCK_STREAM)
tls.bind(('0.0.0.0', 8443))
tls.listen(5)
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile="cert.pem", keyfile="private_key.pem")
connectionID = 0
global comm_context
comm_context = {}

def client_handling(connection):
    global connectionID
    connectionID += 1
    comm_context["id"] = connectionID
    print(f'Client {connectionID} connected')
    connection.sendall(str(connectionID).encode())
    public_key = serialization.load_pem_public_key(connection.recv(2048))
    auth_message_encrypted_json = connection.recv(2048)
    auth_message_encrypted = comm.encoded_json_to_obj(auth_message_encrypted_json)
    auth_message_json = comm.sym_decrypt(auth_message_encrypted, private_key, nonce)
    auth_message = comm.encoded_json_to_obj(auth_message_json)
    username = auth_message["message"]["username"]
    password = auth_message["message"]["password"]

    # Verify username and password
    if verify_credentials(username, password):
        connection.sendall(comm.message("accept invite", 1, comm_context))
        connection.sendall(comm.obj_to_encoded_json(comm.sym_encrypt(comm.obj_to_encoded_json(str(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)), 'latin1')), public_key, nonce))
        connection.sendall(comm.obj_to_encoded_json(comm.sym_encrypt(comm.obj_to_encoded_json(nonce), public_key, nonce)))
        while True:
            try:
                data = connection.recv(1024)
                parsed_data = comm.encoded_json_to_obj(data)
                print(parsed_data)
            except Exception as e:
                print(str(e))
                print(f'Client {connectionID} disconnected')
                break
    else:
        connection.sendall(comm.message("reject invite", 1, comm_context))
        print(f'Client {connectionID} rejected')
        print(f'Client {connectionID} disconnected')

def verify_credentials(username, password):
    # TODO: Implement your logic to verify the username and password
    # For example, you can check against a database or a hardcoded list of valid credentials
    return username == "admin" and password == "password"

try:
    while True:
        connection, address = tls.accept()
        t = threading.Thread(target=client_handling, args=(connection,))
        t.daemon = True
        t.start()
except KeyboardInterrupt:
    tls.close()
    sys.exit()
