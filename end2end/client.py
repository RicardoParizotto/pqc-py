# Client
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

# Define server address and port
SERVER_ADDRESS = ('localhost', 5000)

# Create UDP socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

message = "Prove yourself!"

sigalg = "ML-DSA-44"
verifier = oqs.Signature(sigalg)

# Send the message to the server
client_socket.sendto(message.encode(), SERVER_ADDRESS)

print(f"Sent: {message}")

# Receive response from the server
data, server_address = client_socket.recvfrom(8000)


print(f"Received: {data.decode()} from {server_address[0]}:{server_address[1]}")

rcv_data = data.decode()
sig_data = json.loads(rcv_data)

# Extrai os campos do dicionário
rcv_message = sig_data["message"].encode("utf-8")  # converte de volta para bytes
signature = bytes.fromhex(sig_data["signature"])
public_key = bytes.fromhex(sig_data["public_key"])


# Verifier verifies the signature
is_valid = verifier.verify(rcv_message, signature, public_key)

logger.info("Valid signature? %s", is_valid)

client_socket.close()
