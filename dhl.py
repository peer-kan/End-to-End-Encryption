import comm
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def send(conn, to, context):
    #set parameters
    parameters = dh.generate_parameters(generator=2, key_size=512)
    p = parameters.parameter_numbers().p
    g = parameters.parameter_numbers().g
    print(p, g)
    #send p,g
    conn.send(comm.message(p, to, context))
    conn.send(comm.message(g, to, context))

    #send public value
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    conn.send(comm.message(public_key.public_numbers().y, to, context))

    #send nonce
    nonce = os.urandom(16)
    conn.send(comm.message(nonce.decode('latin1'), to, context))
    print(nonce)

    #recv peer public value
    y = int(comm.encoded_json_to_obj(conn.recv(1024))['message'])
    peer_public_numbers = dh.DHPublicNumbers(y, parameters.parameter_numbers())
    peer_public_key = peer_public_numbers.public_key()

    #cal shared key
    print('key')
    shared_key = private_key.exchange(peer_public_key)
    print(int.from_bytes(shared_key, 'big'))

    #encrypt data
    derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=None).derive(shared_key)
    cipher = Cipher(algorithms.AES256(derived_key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    decryptor = cipher.decryptor()

    return derived_key, encryptor, decryptor

    
def recv(conn, to, context):
    #recv p,g
    p = int(comm.encoded_json_to_obj(conn.recv(1024))['message'])
    g = int(comm.encoded_json_to_obj(conn.recv(1024))['message'])
    print(p,g)
    #set parameters
    pn = dh.DHParameterNumbers(p, g)
    parameters = pn.parameters()

    #recv public peer value
    y = int(comm.encoded_json_to_obj(conn.recv(1024))['message'])
    peer_public_numbers = dh.DHPublicNumbers(y, parameters.parameter_numbers())
    peer_public_key = peer_public_numbers.public_key()

    #recv nonce
    nonce = comm.encoded_json_to_obj(conn.recv(1024))['message'].encode('latin1')
    print(nonce)

    #send public value
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    conn.send(comm.message(public_key.public_numbers().y, to, context))

    #cal shared key
    shared_key = private_key.exchange(peer_public_key)
    print('key')
    print(int.from_bytes(shared_key, 'big'))

    derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=None).derive(shared_key)
    cipher = Cipher(algorithms.AES256(derived_key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    decryptor = cipher.decryptor()
    
    return derived_key, encryptor, decryptor
