from socket import create_connection
from ssl import SSLContext, PROTOCOL_TLS_CLIENT


hostname='example.org'
ip = '127.0.0.1'
port = 8443
context = SSLContext(PROTOCOL_TLS_CLIENT)
context.load_verify_locations('cert.pem')

with create_connection((ip, port)) as client:
    with context.wrap_socket(client, server_hostname=hostname) as tls:
        print(f'Using {tls.version()}\n')
        while True:
            message = input("Enter message to send: ")
            tls.sendall(message.encode())
            data = tls.recv(1024)
            if not data:
                break
            print(f"Received: {data.decode()}")
