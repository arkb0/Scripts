from typing import List, Optional, Tuple

# A Sudoku grid: 9x9, with zeroes marking blanks to be solved.
# Example board
# 1-9: Digits (face values)
# 0: Unfilled
board: List[List[int]] = [
  [7, 8, 0, 4, 0, 0, 1, 2, 0],
  [6, 0, 0, 0, 7, 5, 0, 0, 9],
  [0, 0, 0, 6, 0, 1, 0, 7, 8],
  [0, 0, 7, 0, 4, 0, 2, 6, 0],
  [0, 0, 1, 0, 5, 0, 9, 3, 0],
  [9, 0, 4, 0, 6, 0, 0, 0, 5],
  [0, 7, 0, 3, 0, 0, 0, 1, 2],
  [1, 2, 0, 0, 0, 7, 4, 0, 0],
  [0, 4, 9, 2, 0, 6, 0, 0, 7]
]

# The character to display unfilled cells
# A visual stand-in for empty slots, easier to read than (the internal representation) zero.
UNFILLED_CHAR: str = '_'

# Face value, or convert 0 to _
# A helper: ensures the board prints neatly, hiding zeroes.
def get_num(n: int) -> str:
  return str(n) if n != 0 else UNFILLED_CHAR

# Print the whole board
def print_board(b: List[List[int]]) -> None:
  for i in range(len(b)):

    # Horizontal separator
    if i % 3 == 0 and i != 0:
      print('- - - - - - - - - - - - -')
    # Every third row, draw a line to mark sub-grids.

    for j in range(len(b[0])):
      if j % 3 == 0 and j != 0:
        # Vertical dividers for sub-grids.
        print(' | ', end = '')
      elif j == 0:
        # Leading space
        print(' ', end = '')

      # Each cell printed with spacing, final one ends the line.
      if j == 8:
        print(get_num(b[i][j])) # Just the number + newline
      else:
        print(f'{get_num(b[i][j])} ', end = '') # The number + a space

# Find an empty cell (0)
# Scans the board, returns coordinates of the first blank.
def find_empty(b: List[List[int]]) -> Optional[Tuple[int, int]]:
  for i in range(len(b)):
    for j in range(len(b)):
      if b[i][j] == 0: # 0 signifies empty/unfilled
        return (i, j) # (row, col)
  return None # Not-found sign

# Validity check: ensures a number fits Sudoku rules (row, column, sub-grid).
# Find if the current board is valid
# pos: (row, col)
def valid(b: List[List[int]], n: int, pos: Tuple[int, int]) -> bool:
  # Check row
  for i in range(len(b[0])):
    # If any column other than the pos column contains the same number
    if b[pos[0]][i] == n and pos[1] != i:
      return False
    
  # Check column
  for i in range(len(b)):
    # If any row other than the pos row contains the same number
    if b[i][pos[1]] == n and pos[0] != i:
      return False
    
  # Check pos's 3x3 square
  # Integer division to get the box
  box_x, box_y = pos[1] // 3, pos[0] // 3

  # Checm from the current box to the next
  for i in range(box_y * 3, (box_y + 1) * 3):
    for j in range(box_x * 3, (box_x + 1) * 3):
      # If another cell contains the same number
      if b[i][j] == n and (i, j) != pos:
        return False
  
  return True

# Recursive Sudoku solver
# Classic backtracking: fill a blank, recurse, undo if stuck.
def solve(b: List[List[int]]) -> bool:
  # Find the first empty cell
  find: Optional[Tuple[int, int]] = find_empty(b)

  # Solution found if no empty cells in the input
  if not find:
    return True
  # row, col found
  else:
    row, col = find

  # Try each number 1 to 9 (inclusive)
  for i in range(1, 10):
    # If valid
    if valid(b, i, (row, col)):
      # Make the assignment
      b[row][col] = i
      
      # Accept provisionally and continue
      if solve(b):
        return True
      
      # Else: Reset to unassigned
      b[row][col] = 0
  return False

# Entry point: prints the puzzle, solves it, then prints the solution.
def main() -> None:
  print_board(board)
  print('\n-------------------------\n')
  solve(board)
  print_board(board)

# Standard Python idiom: run main only if executed directly.
if __name__ == '__main__':
  main()
