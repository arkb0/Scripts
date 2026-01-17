# ANSI colours
RESET: str = '\033[0m'   # Reset colour back to terminal default
RED: str = '\033[31m'    # Red for deletions
GREEN: str = '\033[32m'  # Green for additions
YELLOW: str = '\033[33m' # Yellow available for emphasis, though unused here

# Handy function to colour a line of text with a specified colour
# Automatically resets the colour at the end of the line
def colour_text(text: str, colour: str) -> str:
  return f'{colour}{text}{RESET}'   # Wraps text in ANSI codes for display
