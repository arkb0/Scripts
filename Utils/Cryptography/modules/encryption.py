# Cryptographically secure randomness for keys and nonces
import secrets # Like random, but more secure
# Authenticated encryption with associated data (AEAD) via AES-GCM
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# RSA primitives and OAEP padding for secure asymmetric operations
from cryptography.hazmat.primitives.asymmetric import rsa, padding
# Hash functions used within OAEP (SHA-256)
from cryptography.hazmat.primitives import hashes

# Symmetric Encryption
# Encrypts and decrypts a message using AES-GCM; returns key, ciphertext, and recovered plaintext
def aes_ed(message):
  # 256-bit AES key for strong symmetric security
  key = secrets.token_bytes(32)
  # Initialisation vector (nonce) for AES-GCM; 12 bytes is standard and efficient
  nonce = secrets.token_bytes(12)
  # AES-GCM context bound to the generated key
  aes = AESGCM(key)

  # Prepend nonce to ciphertext for transport; AAD omitted (None)
  ciphertext = nonce + aes.encrypt(nonce, message.encode(), None)
  # Split nonce and ciphertext to decrypt; recover original plaintext
  plaintext = aes.decrypt(ciphertext[:12], ciphertext[12:], None)

  # Hex-encode key and ciphertext for display; decode plaintext to text
  return key.hex(), ciphertext.hex(), plaintext.decode()

# Asymmetric Encryption
# Demonstrates RSA encryption/decryption with OAEP; generates ephemeral keys per call
def rsa_ed(message):
  # Generate a fresh RSA private key (2048-bit) with standard public exponent
  private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
  # Derive the corresponding public key for encryption
  public_key = private_key.public_key()

  # Encrypt the message using RSA-OAEP with SHA-256 for both MGF1 and hash
  ciphertext = public_key.encrypt(
    message.encode(),
    padding.OAEP( # Optimal asymmetric encryption padding
      mgf=padding.MGF1(algorithm=hashes.SHA256()), # Mask generation function
      algorithm=hashes.SHA256(),
      label=None
    )
  )

  # Decrypt the ciphertext using the private key and matching OAEP parameters
  plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP( # Optimal asymmetric encryption padding
      mgf=padding.MGF1(algorithm=hashes.SHA256()), # Mask generation function
      algorithm=hashes.SHA256(),
      label=None
    )
  )

  # Return hex-encoded ciphertext and decoded plaintext for readability
  return ciphertext.hex(), plaintext.decode()

# Simple self-test: exercise both AES and RSA paths with a sample message
if __name__ == '__main__':
  print(aes_ed('Saluton, Mondo!'), end='\n\n')
  print(rsa_ed('Saluton, Mondo!'), end='\n\n')
