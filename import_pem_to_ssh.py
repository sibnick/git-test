from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# Assuming you have the raw private key bytes (as an example, replace 'your_private_key_bytes' with actual bytes)
private_key_bytes = bytes.fromhex("f3d1b6f23d9d0df2dec233b7ded22662c55b4fb5fd2b3a3ffeb83d6834562456")  # The private key must be 32 bytes long
private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)

# Serialize the private key in OpenSSH format
private_key_ssh_format = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.OpenSSH,
    encryption_algorithm=serialization.NoEncryption()
)

# Serialize the public key in OpenSSH format
public_key_ssh_format = private_key.public_key().public_bytes(
    serialization.Encoding.OpenSSH,
    serialization.PublicFormat.OpenSSH
)

# Write the private key to a file
with open('id_ed25519_test', 'wb') as f:
    f.write(private_key_ssh_format)

# Write the public key to a file with the appropriate comment
with open('id_ed25519_test.pub', 'wb') as f:
    f.write(public_key_ssh_format + b' your@email.com')

# Setting the file permissions (this should be done in the command line for security)
# chmod 600 id_ed25519
# chmod 644 id_ed25519.pub

