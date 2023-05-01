import json
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def obj_to_encoded_json(obj):
    return json.dumps(obj).encode()


def encoded_json_to_obj(byte):
    print(byte)
    return json.loads(byte.decode())


def message(message, to, context):
    obj = {
        "type": "message",
        "from": context['id'],
        "to": to,
        "message": message,
    }
    return obj_to_encoded_json(obj)


def sym_encrypt(plain_text, encryptor):
    return (encryptor.update(plain_text) + encryptor.finalize()).decode('latin1')


def sym_decrypt(cipher_text, decryptor):
    return decryptor.update(cipher_text.encode('latin1')) + decryptor.finalize()
