# Password strength estimation library (uses heuristics and common patterns)
from zxcvbn import zxcvbn
# Secure password input without echoing to terminal
from getpass import getpass
# Modern password hashing library (bcrypt algorithm)
import bcrypt

# Import colour utilities for terminal feedback
from .ansicolours import colour_text, RED, YELLOW, GREEN

# Assess password strength using zxcvbn scoring (0–4 scale)
def check_strength(password):
  # Analyse password and return structured feedback
  result = zxcvbn(password)
  score = result['score']
  # Score of 3 indicates acceptable strength
  if score == 3:
    response = f'{colour_text("Strong Enough", YELLOW)} (3/4)'
  # Score of 4 indicates very strong password
  elif score == 4:
    response = f'{colour_text("Very Strong", GREEN)} (4/4)'
  # Scores 0–2 are considered weak
  else:
    feedback = result.get('feedback')
    warning = feedback.get('warning')
    suggestions = feedback.get('suggestions')
    response = f'{colour_text("Weak", RED)} ({score}/4)'
    # Provide warning and improvement suggestions
    response += f'\nWarning: {warning}'
    response += f'\nSuggestions: {" ".join(suggestions)}'
  # Return formatted strength report
  return response

# Hashing a password for storage
def hash_pw(password):
  # Generate a random salt to prevent identical hashes for identical passwords
  salt = bcrypt.gensalt()
  # Hash password with salt using bcrypt algorithm
  hashed = bcrypt.hashpw(password.encode(), salt)
  return hashed

# Verify a password attempt against stored bcrypt hash
def verify_pw(pw_attempt, hashed):
  # If attempt matches stored hash, authentication succeeds
  if bcrypt.checkpw(pw_attempt.encode(), hashed):
    return f'{colour_text("Authenticated", GREEN)}. Access granted.'
  # Otherwise, deny access
  return f'{colour_text("Incorrect password", RED)}. Access denied.'

# Demonstration loop when run directly
if __name__ == '__main__':
  while True:
    # Prompt user for password input
    password = getpass('Enter a password to check its strength: ')
    response = check_strength(password)
    print(response)

    # If weak, prompt user to try again
    if response.startswith(f'{colour_text("Weak", RED)}'):
      print('Please choose a stronger password.')
    else:
      break

  # Hash the accepted password
  hashed_pw = hash_pw(password)
  print(f'Hashed: {hashed_pw}')
  
  # Prompt user to re-enter password for verification
  attempt = getpass('Re-enter the password to verify.')
  print(verify_pw(attempt, hashed_pw))
