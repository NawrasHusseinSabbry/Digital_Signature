import time
import tracemalloc
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import binascii

# Start tracing memory allocations
tracemalloc.start()

# Step 1: Generate RSA Private and Public Keys
print("Generating RSA private and public keys...")
start_time = time.time()
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()
key_gen_time = time.time() - start_time

# Raw key lengths (actual cryptographic material)
raw_private_key_length = len(key.export_key(format='DER'))
raw_public_key_length = len(key.publickey().export_key(format='DER'))

# PEM key lengths (with headers, footers, and base64 encoding)
pem_private_key_length = len(private_key)
pem_public_key_length = len(public_key)

# Save keys to files
with open("private.key", "wb") as file_out:
    file_out.write(private_key)
with open("public.key", "wb") as file_out:
    file_out.write(public_key)

# Print the keys and their lengths
print(f"Keys generated and saved successfully in {key_gen_time:.4f} seconds!\n")
print("Private Key (PEM format):\n", private_key.decode())
print("Public Key (PEM format):\n", public_key.decode(), "\n")

# Print the lengths of the keys
print(f"Raw Length of Private Key (DER format): {raw_private_key_length} bytes")
print(f"Raw Length of Public Key (DER format): {raw_public_key_length} bytes\n")
print(f"PEM Length of Private Key: {pem_private_key_length} bytes")
print(f"PEM Length of Public Key: {pem_public_key_length} bytes\n")

# Step 2: Ask the user to enter a message to sign
user_message = input("Enter the message you want to sign: ").encode()

# Create a SHA-256 hash of the message
print("Hashing the message using SHA-256...")
start_time = time.time()
h = SHA256.new(user_message)
hash_time = time.time() - start_time
print(f"Message hashed successfully in {hash_time:.4f} seconds!\n")
print(f"Length of Hashed Message: {len(h.digest())} bytes\n")

# Step 3: Sign the message using the private key
print("Signing the message with the private key...")
start_time = time.time()
signer = pkcs1_15.new(RSA.import_key(private_key))
signature = signer.sign(h)
sign_time = time.time() - start_time
print(f"Message signed successfully in {sign_time:.4f} seconds!\n")

# Display the signature (in hexadecimal format for readability)
print("Signature (hex format):", binascii.hexlify(signature).decode())
print(f"Length of Signature: {len(signature)} bytes\n")

# Save the signature to a file
with open("signature.pem", "wb") as file_out:
    file_out.write(signature)
print("Signature saved successfully to 'signature.pem'!\n")

# Step 4: Verification process
print("Explanation:")
print("The message and the signature are now supposed to be sent to the receiver, then the receiver will try to verify if the signature is correct or not.")
print("\n--- Instructions for Copying and Pasting ---")
print("1. Write (or copy) the message as the receiver is supposed to receive it, and then paste it into the terminal.")
print("2. Write (or copy) the signature as the receiver is supposed to receive it (hexadecimal format), and then paste it into the terminal.")

# Input for the received message
received_message = input("Enter the received message: ").encode()

# Input the signature in hexadecimal format
received_signature_hex = input("Enter the received signature (hex format): ")
received_signature = binascii.unhexlify(received_signature_hex)

# Step 5: Verify the signature using the public key
print("Receiver is verifying the signature...\n")
start_time = time.time()
try:
    verifier = pkcs1_15.new(RSA.import_key(public_key))
    verifier.verify(SHA256.new(received_message), received_signature)
    verify_time = time.time() - start_time
    print(f"Verification successful: The signature is valid. Verification took {verify_time:.4f} seconds.\n")
except (ValueError, TypeError):
    verify_time = time.time() - start_time
    print(f"Verification failed: The signature is invalid. Verification took {verify_time:.4f} seconds.\n")

# Measure memory usage
current, peak = tracemalloc.get_traced_memory()
print(f"\nCurrent memory usage: {current / 10**6:.6f} MB")
print(f"Peak memory usage: {peak / 10**6:.6f} MB")
tracemalloc.stop()
