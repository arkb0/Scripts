import asyncio
import aiohttp
import argparse

# Console display colours using ANSI escape codes
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

# Mapping of platform names to their profile URL patterns
PLATFORMS = {
  'X (Twitter)': 'https://x.com/{}', # Might need to change things to accept Twitter's HUUUUGE cookie
  'Reddit': 'https://www.reddit.com/user/{}',
  'GitHub': 'https://github.com/{}',
  'Instagram': 'https://www.instagram.com/{}/',
  'TikTok': 'https://www.tiktok.com/@{}',
  'Medium': 'https://medium.com/@{}'
}

async def check_username(session, platform, url):
  """
  Perform an HTTP GET request to check whether a username exists on a platform.
  Returns a tuple: (platform_name, True/False/'Unknown...').
  """
  try:
    async with session.get(url) as resp:
      # 200 usually means the profile exists
      if resp.status == 200:
        return platform, True
      # 404 means the profile does not exist
      elif resp.status == 404:
        return platform, False
      # Any other status is treated as unknown
      else:
        return platform, f'Unknown status: {resp.status}'
  except Exception as e:
    # Network errors, timeouts, etc.
    return platform, f'Exception: {e}'
  
async def enumerate_username(username):
  """
  Creates a shared HTTP session and checks the username across all platforms
  concurrently. Returns a list of (platform, status) tuples.
  """
  timeout = aiohttp.ClientTimeout(total=10)

  # Create a session with a custom User-Agent and global timeout
  async with aiohttp.ClientSession(
    headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 15.7; rv:146.0) Gecko/20100101 Firefox/146.0"},
    timeout=timeout
  ) as session:

    tasks = []
    for platform, url in PLATFORMS.items():
      full_url = url.format(username)
      # Schedule each check as an asynchronous task
      tasks.append(asyncio.create_task(check_username(session, platform, full_url)))

    # Run all tasks concurrently and gather results
    results = await asyncio.gather(*tasks)
    return results
  
def print_results(username, results):
  """
  Print human‑readable results to the console with colour coding.
  """
  print(f'===== Username Enumeration for `{username}` =====')
  for platform, status in results:
    if status is True:
      print(f'{GREEN}[+] {platform}: FOUND.{RESET}')
    elif status is False:
      print(f'{RED}[-] {platform}: Not found.{RESET}')
    else:
      # Covers unknown statuses and exceptions
      print(f'{YELLOW}[?] {platform}: {status}{RESET}')

def main():
  """
  Parse command‑line arguments, run the enumeration, and optionally output JSON.
  """
  parser = argparse.ArgumentParser(description='Public social media username enumerator.')
  parser.add_argument('username', help='Username to lookup')
  parser.add_argument('--json', action='store_true', help='Save results as a JSON')
  args = parser.parse_args()

  # Run the asynchronous enumeration
  results = asyncio.run(enumerate_username(args.username))

  # Print coloured CLI output
  print_results(args.username, results)

  # Optional JSON output
  if args.json:
    import json
    out = {
      'username': args.username,
      'results': {
        platform: (
          'found' if status is True else
          'not_found' if status is False else
          f'Unknown: {status}'
        )
        for platform, status in results
      }
    }
    print(json.dumps(out, indent=2))

if __name__ == '__main__':
  main()
