from PyPDF2 import PdfReader

import logging
import oqs
import json
import hashlib
from sys import stdout
from pprint import pformat



logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(logging.StreamHandler(stdout))

logger.info("liboqs version: %s", oqs.oqs_version())
logger.info("liboqs-python version: %s", oqs.oqs_python_version())
logger.info(
    "Enabled signature mechanisms:\n%s",
    pformat(oqs.get_enabled_sig_mechanisms(), compact=True),
)


# signature mechanism Module-Lattice-Based Digital Signature Standard
sigalg = "ML-DSA-44"   
# Create signer with sample signature mechanisms
signer = oqs.Signature(sigalg) 
signer_public_key = signer.generate_keypair()


def hash_dict(data):
    dict_string = json.dumps(data, sort_keys=True).encode('utf-8')
    return hashlib.sha256(dict_string).hexdigest()

def read_pdf_metadata(pdf_path):
    """
    Reads and prints metadata from a PDF file.

    Args:
        pdf_path (str): The path to the PDF file.
    """
    try:
        with open(pdf_path, 'rb') as file:
            reader = PdfReader(file)
            metadata = reader.metadata
            if metadata:
                print("Metadata:")
                for key, value in metadata.items():
                    print(f"{key}: {value}")
                return metadata
            else:
                print("No metadata found in this PDF.")
    except FileNotFoundError:
        print(f"Error: File not found at '{pdf_path}'")
    except Exception as e:
        print(f"An error occurred: {e}")
    return False

# Example usage:
pdf_file_path = 'teste.pdf'
pdf_metadata = read_pdf_metadata(pdf_file_path)

if(pdf_metadata):
    # Signer signs the pdf
    pdf_hash = hash_dict(pdf_metadata)
    print(pdf_hash)
    signature = signer.sign(pdf_hash.encode())
    print(signature)
