# Server 
import socket
import logging
from pprint import pformat
from sys import stdout

import oqs
import json

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(logging.StreamHandler(stdout))

logger.info("liboqs version: %s", oqs.oqs_version())
logger.info("liboqs-python version: %s", oqs.oqs_python_version())
logger.info(
    "Enabled signature mechanisms:\n%s",
    pformat(oqs.get_enabled_sig_mechanisms(), compact=True),
)

message = b"This is the message to sign"

# Define server address and port
SERVER_ADDRESS = ('localhost', 5000)

# Create UDP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind the socket to the server address
server_socket.bind(SERVER_ADDRESS)

print(f"Server listening on {SERVER_ADDRESS[0]}:{SERVER_ADDRESS[1]}")

# signature mechanism Module-Lattice-Based Digital Signature Standard
sigalg = "ML-DSA-44"   

# Create signer with sample signature mechanisms
signer = oqs.Signature(sigalg) 
signer_public_key = signer.generate_keypair()


# Signer signs the message
signature = signer.sign(message)


while True:
    # Receive data and client address
    data, client_address = server_socket.recvfrom(8000)
    
    print(f"Received {data.decode()} from {client_address[0]}:{client_address[1]}")
    
    if data.decode() == "Prove yourself!":
        # Send back the received data as confirmation
        message_dict = {
            "message": message.decode('utf-8'),
            "signature": signature.hex(),
            "public_key": signer_public_key.hex() 
        }
        print(len(json.dumps(message_dict).encode()))
        server_socket.sendto((json.dumps(message_dict)).encode(), client_address)
