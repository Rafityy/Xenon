#!/usr/bin/python3

from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Hash import HMAC, SHA256
import sys

# Constants
AES_KEY_BASE64 = "qFfytoI59K4cUXl8t0Eub0rZnF66rjmcr8DLB2kGHIQ=" #your Base64-encoded AES key
AES_KEY_SIZE = 32  # AES-256 requires a 32-byte key
IV_SIZE = 16  # AES CBC mode IV size
HMAC_SIZE = 32  # SHA-256 HMAC size
UUID_SIZE = 36  # Size of the UUID in bytes

def decode_base64(data):
    """Decode Base64-encoded data."""
    try:
        return b64decode(data)
    except Exception as e:
        print(f"Failed to decode Base64: {e}")
        sys.exit(1)

def verify_hmac(key, data, expected_hmac):
    """Verify the HMAC-SHA256 of the data."""
    h = HMAC.new(key, digestmod=SHA256)
    h.update(data)
    try:
        h.verify(expected_hmac)
        print("HMAC verification successful.")
        return True
    except ValueError:
        print("HMAC verification failed.")
        return False

def decrypt_aes_cbc(key, iv, ciphertext):
    """Decrypt AES-256-CBC encrypted data."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(ciphertext)

def remove_pkcs7_padding(data):
    """Remove PKCS7 padding from the decrypted data."""
    try:
        return unpad(data, AES.block_size)
    except ValueError as e:
        print(f"Invalid PKCS7 padding: {e}")
        sys.exit(1)

def format_bytes_as_hex(data):
    """Format bytes as a string of hexadecimal values (e.g., 0x00 0x01 0x02...)."""
    return " ".join(f"{byte:02X}" for byte in data)

def decrypt_file(file_path):
    """Read, decode, verify HMAC, and decrypt the AES-encrypted file."""
    with open(file_path, "rb") as f:
        # Read the Base64-encoded encrypted file data
        base64_data = f.read()

    # Decode the entire buffer from Base64
    decoded_data = decode_base64(base64_data)

    # Ensure the buffer is large enough to contain UUID, IV, ciphertext, and HMAC
    if len(decoded_data) < (UUID_SIZE + IV_SIZE + HMAC_SIZE):
        print("File is too small to contain necessary data.")
        sys.exit(1)

    # Extract UUID, IV, ciphertext, and HMAC
    uuid = decoded_data[:UUID_SIZE]  # 36 bytes UUID (not used in decryption)
    iv = decoded_data[UUID_SIZE:UUID_SIZE + IV_SIZE]  # Next 16 bytes IV
    hmac_offset = -HMAC_SIZE  # Last 32 bytes HMAC
    ciphertext = decoded_data[UUID_SIZE + IV_SIZE:hmac_offset]  # Ciphertext
    hmac_provided = decoded_data[hmac_offset:]  # Provided HMAC

    print(f"uuid = {uuid}")
    print(f"IV = {format_bytes_as_hex(iv)}")
    print(f"hmac_provided = {format_bytes_as_hex(hmac_provided)}")
    

    # Decode the AES key from Base64
    aes_key = decode_base64(AES_KEY_BASE64)
    if len(aes_key) != AES_KEY_SIZE:
        print(f"Invalid AES key size. Expected {AES_KEY_SIZE} bytes, got {len(aes_key)} bytes.")
        sys.exit(1)

    # Verify HMAC before decrypting
    if not verify_hmac(aes_key, decoded_data[UUID_SIZE: hmac_offset], hmac_provided):
        print("Aborting decryption due to HMAC verification failure.")
        sys.exit(1)

    # Decrypt the ciphertext using AES-256-CBC
    decrypted_data = decrypt_aes_cbc(aes_key, iv, ciphertext)

    # Remove PKCS7 padding
    decrypted_data = remove_pkcs7_padding(decrypted_data)

    # Output the decrypted data in hexadecimal byte format
    print("Decrypted Data (Hex Bytes):")
    print(format_bytes_as_hex(decrypted_data))
    print("Raw data:")
    print(decrypted_data)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <encrypted_file_path>")
        sys.exit(1)

    encrypted_file_path = sys.argv[1]
    decrypt_file(encrypted_file_path)
