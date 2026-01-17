# Standard library for hashing algorithms (SHA-256 used here)
import hashlib

# Import colour utilities for terminal output
from .ansicolours import colour_text, RED, GREEN

# Example snippet (commented out) showing how to hash a simple string
# text = 'Saluton, Mondo!'
# hash_object = hashlib.sha256(text.encode())
# hash_digest = hash_object.hexdigest()
# print(f'SHA Hash of `{text}` is `{hash_digest}`')

# Compute SHA-256 hash of a file
def hash_file(file_path):
  # Create a new SHA-256 hash object
  h = hashlib.new('sha256')
  # Open file in binary mode for reading
  with open(file_path, 'rb') as file:
    while True:
      # Read file in 1024-byte chunks
      chunk = file.read(1024)
      # Stop when no more data
      if chunk == b'':
        break
      # Update hash with current chunk
      h.update(chunk)
  # Return final digest as hexadecimal string
  return h.hexdigest()

# Compare two files by their SHA-256 hashes
def verify_integrity(file1, file2):
  # Compute hash of first file
  hash1 = hash_file(file1)
  # Compute hash of second file
  hash2 = hash_file(file2)

  # Inform user which files are being checked
  print(f'\nChecking integrity between {file1} and {file2}')

  # If hashes match, files are identical
  if hash1 ==  hash2:
    return f'{colour_text("File INTACT", GREEN)}. No modifications have been made.'
  # Otherwise, files differ and may be unsafe
  return f'{colour_text("File MODIFIED", RED)}. Possibly unsafe.'

# Run demonstration only when this file is executed directly
if __name__ == '__main__':
  # Show SHA-256 hash of a sample file
  print(f'SHA Hash of the file is {hash_file(r"sample_files\sample.txt")}')
  # Compare identical files (expected intact)
  print(verify_integrity(r'sample_files\img1.png', r'sample_files\img1.png'))
  # Compare different files (expected modified)
  print(verify_integrity(r'sample_files\img1.png', r'sample_files\img2.png'))
