# A simple Python diff script.
# Diffs at multiple levels of granularity (line, word, char)
# With ANSI colours on the terminal.

import argparse   # Standard library module for parsing command-line arguments
from typing import List, Tuple, Optional

# ANSI colours
RESET: str = '\033[0m'   # Reset colour back to terminal default
RED: str = '\033[31m'    # Red for deletions
GREEN: str = '\033[32m'  # Green for additions
YELLOW: str = '\033[33m' # Yellow available for emphasis, though unused here

# Handy function to colour a line of text with a specified colour
# Automatically resets the colour at the end of the line
def colour_text(text: str, colour: str) -> str:
  return f'{colour}{text}{RESET}'   # Wraps text in ANSI codes for display

# The finest-grained character-level diff for visualising changes within words
def char_diff(line1: str, line2: str) -> Tuple[str, str]:
  result1: List[str] = []
  result2: List[str] = []         # Buffers for old and new line renderings
  # The longer of the two lines
  max_len: int = max(len(line1), len(line2))

  # for each character
  for i in range(max_len):
    c1: Optional[str] = line1[i] if i < len(line1) else None   # Character from old line
    c2: Optional[str] = line2[i] if i < len(line2) else None   # Character from new line

    # Identical
    if c1 == c2:
      # Append both
      if c1 is not None:
        result1.append(c1)          # Keep unchanged character
        result2.append(c2)
    # Different
    else:
      # Existed
      if c1 is not None:
        # Removed
        result1.append(colour_text(c1, RED))    # Highlight removal
      # Now exists
      if c2 is not None:
        # Added
        result2.append(colour_text(c2, GREEN))  # Highlight addition

  return ''.join(result1), ''.join(result2)     # Return coloured strings

# Fine-grained word-level diff for visualising changes within lines
def word_diff(line1: str, line2: str) -> Tuple[str, str]:
  # Split along ' ' to get the words in each line
  words1: List[str] = line1.split()
  words2: List[str] = line2.split()

  # The longer of the two lines (in terms of the number of words)
  max_len: int = max(len(words1), len(words2))
  result1: List[str] = []
  result2: List[str] = []         # Buffers for old and new line renderings

  # for each word
  for i in range(max_len):
    w1: Optional[str] = words1[i] if i < len(words1) else None   # Word from old line
    w2: Optional[str] = words2[i] if i < len(words2) else None   # Word from new line

    # Identical
    if w1 == w2:
      # Append both
      if w1 is not None:
        result1.append(w1)          # Keep unchanged word
        result2.append(w2)
    # Different
    else:
      # Existed
      if w1 is not None:
        # Removed
        result1.append(colour_text(w1, RED))      # Highlight removal
      # Now exists
      if w2 is not None:
        # Added
        result2.append(colour_text(w2, GREEN))    # Highlight addition

  return ' '.join(result1), ' '.join(result2)    # Return coloured strings

# The overall diff logic to process lines
# This calls word_diff or char_diff internally if a fine-grained diff is requested
def line_diff(
    lines1: List[str],
    lines2: List[str],
    mode: str = 'line',
    show_linenums: bool = True
) -> None:
  # The longer of the two files
  max_len: int = max(len(lines1), len(lines2))

  # For each line
  for i in range(max_len):
    # Lines, stripping only the trailing end
    line1: Optional[str] = lines1[i].rstrip('\n') if i < len(lines1) else None   # Old line
    line2: Optional[str] = lines2[i].rstrip('\n') if i < len(lines2) else None   # New line

    # Format the line numbers if configured
    lineno: str = f'{i + 1:4d} ' if show_linenums else ''              # Right-aligned

    # Display the diff
    # Identical => Just print the content
    if line1 == line2:
      print(f'{lineno}   {line1 if line1 else ""}')               # Unchanged
    # Line added => Line 2 in green
    elif line1 is None:
      print(f'{lineno}+  {colour_text(line2, GREEN)}')
    # Line deleted => Line 1 in red
    elif line2 is None:
      print(f'{lineno}-  {colour_text(line1, RED)}')
    # Special handling for changes within the line, including word-level diffs if asked for
    else:
      # The finest-grained (character-level) diff
      if mode == 'char':
        # Get the character-level diff
        c1, c2 = char_diff(line1, line2)
        # Display the changes
        print(f'{lineno}-  {c1}')
        print(f'{lineno}+  {c2}')
      # Fine-grained (word-level) diff
      elif mode == 'word':
        # Get the word-level diff
        w1, w2 = word_diff(line1, line2)
        # Display the changes
        print(f'{lineno}-  {w1}')
        print(f'{lineno}+  {w2}')
      # Coarse diff: Just display the changed lines as replacements
      else:
        print(f'{lineno}-  {colour_text(line1, RED)}')
        print(f'{lineno}+  {colour_text(line2, GREEN)}')

# Entry point
def main() -> None:
  # Argument parser. THe descriptions are self-explanatory
  parser = argparse.ArgumentParser(description='Simple diff viewer')
  parser.add_argument('file1', help='First file')   # Path to original file
  parser.add_argument('file2', help='Second file')  # Path to modified file
  parser.add_argument('-w', '--word', action='store_true', help='Enable word-level diff')
  parser.add_argument('-c', '--char', action='store_true', help='Enable character-level diff')
  parser.add_argument('-nl', '--no-lineno', action='store_true', help='Disable line numbers')
  
  args = parser.parse_args()   # Parse CLI arguments into a namespace

  # The precedence favours the finer-grained option
  # char > word > line
  # So if both are specified, a char_diff is displayed
  if args.char:
    mode: str = 'char'
  elif args.word:
    mode: str = 'word'
  else:
    mode: str = 'line'

  # Open the input files and read their lines
  with open(args.file1) as f1, open(args.file2) as f2:
    lines1: List[str]
    lines2: List[str]
    lines1, lines2 = f1.readlines(), f2.readlines()   # Lists of strings

  # Diff as configured in the CLI args
  line_diff(lines1, lines2, mode=mode, show_linenums=not args.no_lineno)

if __name__ == '__main__':
  main()   # Run the programme if invoked directly
