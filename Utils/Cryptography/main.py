# Author: Q
# This is our field toolkit for agents in need of digital secrecy.
# Think of it as your personal issue from Q's lab: practical, clever, and just a bit theatrical.

# Import cryptographic and utility modules from our own arsenal
from modules.hash import hash_file, verify_integrity
from modules.encryption import aes_ed, rsa_ed
from modules.password import check_strength, hash_pw, verify_pw
from modules.ansicolours import colour_text, RED
from getpass import getpass

# Present the agent with a menu of available operations
def menu():
  print('\nSelect Operation:')
  print('1. Hash file')
  print('2. Check file integrity')
  print('3. AES Encrypt/Decrypt')
  print('4. RSA Encrypt/Decrypt')
  print('5. Password Manager')
  print('6. Exit\n')

# Main mission briefing and control loop
def main():
  # Greetings from Q-Branch, setting the scene for the agent
  print('''
Initialising Q-Cryptography Toolkit v1.0...

\nWelcome, Agent! Your mission, should you choose to accept it:
- Analyse and hash files to detect tampering.
- Encrypt and decrypt messages with AES and RSA.
- Securely manage passwords and assess their strength.

All systems online. Data protection protocols active.
Prepare to enter the world of digital secrecy!''')
  
  # Continuous loop until agent chooses to exit
  while True:
    menu()

    choice = input('Enter choice (1-6): ')

    # Hashing a file to produce its SHA-256 fingerprint
    if choice == '1':
      file_path = input('Enter file path: ')
      print(f'\nSHA Hash of the file is: {hash_file(file_path)}')
    # Comparing two files to check for tampering
    elif choice == '2':
      file_path1 = input('Enter file path 1: ')
      file_path2 = input('Enter file path 2: ')
      print(verify_integrity(file_path1, file_path2))
    # AES symmetric encryption demonstration
    elif choice == '3':
      message = input('Enter your message: ')
      key, ciphertext, plaintext = aes_ed(message)
      print(f'AES Key: {key}')
      print(f'AES Ciphertext: {ciphertext}')
      print(f'AES Plaintext: {plaintext}')
    # RSA asymmetric encryption demonstration
    elif choice == '4':
      message = input('Enter your message: ')
      ciphertext, plaintext = rsa_ed(message)
      print(f'RSA message, encrypted with a public key: {ciphertext}')
      print(f'RSA message, decrypted with a private key: {plaintext}')
    # Password strength assessment and verification
    elif choice == '5':
      while True:
        password = getpass('Enter a password to check strength: ')
        result = check_strength(password) # Nicely shaken, not stirred?
        print(result)
        
        # Q would frown upon weak passwords; insist on stronger ones
        if result.startswith(f'{colour_text("Weak", RED)}'):
          # I take a ridiculous pleasure in crafting my passwords.
          # It's very pernickety and old-maidish really,
          # but it makes them more interesting when one takes trouble. 
          print('Please choose a stronger password.')
        else:
          break
      
      # Hash the password for storage (bcrypt)
      hashed_pw = hash_pw(password)
      print(f'Hashed password: {hashed_pw}')
      # Verify password by re-entry
      attempt = getpass('Re-enter the password to verify: ')
      print(verify_pw(attempt, hashed_pw))
    # Exit the toolkit gracefully
    elif choice == '6':
      break
    else:
      print('Invalid choice.')

  # Final farewell from Q-Branch; mission complete
  print('\nAgent, you are exiting your Q-Cryptography Toolkit. Stay sharp and secure out there!')


# Entry point; launch the toolkit when run directly
if __name__ == '__main__':
  main()
