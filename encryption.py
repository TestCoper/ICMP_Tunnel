from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Generate a new RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Serialize the public key
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Generate a random symmetric key
symmetric_key = os.urandom(32)  # 256-bit key for AES-256

# Encrypting data with the symmetric key
cipher = Cipher(algorithms.AES(symmetric_key), modes.ECB())
encryptor = cipher.encryptor()
encrypted_data = encryptor.update(b'') + encryptor.finalize()

# Encrypting the symmetric key with the public key
encrypted_symmetric_key = public_key.encrypt(
    symmetric_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Serialize the private key
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Decrypting the symmetric key with the private key
private_key = serialization.load_pem_private_key(
    private_key_pem,
    password=None
)
decrypted_symmetric_key = private_key.decrypt(
    encrypted_symmetric_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Decrypting the encrypted data with the symmetric key
cipher = Cipher(algorithms.AES(decrypted_symmetric_key), modes.ECB())
decryptor = cipher.decryptor()
decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

print("Original message:", b'This is a secret message.')
print("Decrypted message:", decrypted_data)
