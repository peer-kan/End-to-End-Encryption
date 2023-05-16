import json
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def obj_to_encoded_json(obj):
    return json.dumps(obj).encode()


def encoded_json_to_obj(byte):
    return json.loads(byte.decode())


def message(message, to, context):
    obj = {
        "type": "message",
        "from": context['id'],
        "to": to,
        "message": message,
    }
    return obj_to_encoded_json(obj)


def command(command, context):
    obj = {
        "type": "command",
        "from": context['id'],
        "to": 0,
        "command": command,
    }
    return obj_to_encoded_json(obj)


def sym_encrypt(plaintext, key, nonce):
    encryptor = Cipher(
        algorithms.AES256(key),
        modes.CTR(nonce)
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext.decode('latin1')


def sym_decrypt(ciphertext, key, nonce):
    decryptor = Cipher(
        algorithms.AES256(key),
        modes.CTR(nonce)
    ).decryptor()
    plaintext = decryptor.update(ciphertext.encode('latin1')) + decryptor.finalize()
    return plaintext.decode()