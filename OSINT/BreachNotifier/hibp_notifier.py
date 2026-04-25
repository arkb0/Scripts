'''
Automated Password Breach Notifier
Checks emails using the Have I Been Pwned (HIBP) API
'''

# Import standard libraries for HTTP requests, system arguments, and data handling
import requests
import sys
import json
from typing import List, Dict
from datetime import datetime

# Define a class to encapsulate interactions with the Have I Been Pwned API
class BreachChecker:
  # Initialise the checker with an optional API key and set up base configuration
  def __init__(self, api_key: str = None):
    # Store the provided key to authorise requests
    self.api_key = api_key
    # Define the primary endpoint for the HIBP service
    self.base_url = 'https://haveibeenpwned.com/api/v3'
    # Define the necessary headers for the request, including the required User-Agent
    self.headers = {
      'User-Agent': 'd35-breach-checker',
      # Default to the test API key (see https://haveibeenpwned.com/api/v3#TestAPIKey)
      'hibp-api-key': api_key if api_key else '00000000000000000000000000000000'
    }

  # Execute a single email look-up against the breach database
  def check_email(self, email: str) -> Dict:
    '''Check if an email has been pwned'''
    try:
      # Normalise email
      # Sanitise the input to ensure it is lowercase and free of leading/trailing whitespace
      email = email.strip().lower()

      # Get breaches for this email
      # Construct the URL for the specific account look-up
      url = f'{self.base_url}/breachedaccount/{email}'
      # Perform the GET request with a 10-second timeout to avoid hanging
      response = requests.get(url, headers=self.headers, timeout=10)

      # Results and Errors...
      # Status 200 indicates that the email was successfully found in at least one breach
      if response.status_code == 200:
        breaches = response.json()
        return {
          'email': email,
          'breached': True,
          'breach_count': len(breaches),
          'breaches': breaches
        }
      # Status 404 indicates the email has not been found in any known data breaches
      elif response.status_code == 404:
        return {
          'email': email,
          'breached': False,
          'breach_count': 0,
          'breaches': [],
          'error': f'API returned status {response.status_code}.'
        }
      # Handle other HTTP status codes (e.g., 401 Unauthorised or 429 Too Many Requests)
      else: # Catch-all
        return {
          'email': email,
          'breached': False,
          'error': f'API returned status {response.status_code}.'
        }

    # Handle connection issues, timeouts, or DNS failures gracefully
    except requests.exceptions.RequestException as e:
      return {
        'email': email,
        'breached': False,
        'error': str(e)
      }
    
  # Iterate through a list of email addresses to perform batch checks
  def check_emails(self, emails: List[str]) -> List[Dict]:
    '''Check multiple emails for pwnage'''
    results = []

    # Process each email address individually
    for em in emails:
      print(f'Checking: {em} ...')
      result = self.check_email(em)
      results.append(result)
    
    return results
  
  # Generate a human-readable summary in the terminal
  def print_report(self, results: List[Dict]):
    '''Print formatted breach check report'''
    print('\n' + '='*80)
    print('PWNAGE REPORT')
    # Use the current system time to timestamp the report generation
    print(f'Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}')
    print('='*80 + '\n')

    breached_count = 0
    safe_count = 0

    # Iterate through the results to categorise and display them
    for result in results:
      # Check if the 'breached' flag is set to true in the result dictionary
      if result.get('breached'):
        breached_count += 1
        print(f'❌ BREACHED: {result["email"]}')
        print(f'   Found in {result["breach_count"]} breach(es):')
        # Display details for the first five breaches to keep the output manageable
        for breach in result['breaches'][:5]:  # Show first 5
          # Extract specific metadata about each security incident
          print(breach)
          name = breach.get('Name', 'Unknown Name')
          date = breach.get('BreachDate', 'Unknown Date')
          print(f'   • {name} - {date}')
        # Notify the user if more breaches exist than are currently displayed
        if len(result['breaches']) > 5:
          print(f'   ... and {len(result["breaches"]) - 5} more')
        print()
      # Handle cases where the API request failed
      elif result.get('error'):
        print(f'⚠️  ERROR: {result["email"]} - {result["error"]}\n')
      # Confirm accounts that appear to be safe based on current data
      else:
        safe_count += 1
        print(f'✅ SAFE: {result["email"]}\n')

    # Print final tallies for the entire session
    print('='*80)
    print(f'SUMMARY: {breached_count} breached, {safe_count} safe, {len(results)} total')
    print('='*80)
    
# Driver
# Define the main entry point for script execution
def main():
  api_key = None # Add your HIBP API key here for higher rate limits
  # Instantiate the checker logic
  checker = BreachChecker(api_key)

  # Read emails from a file or the command line
  # Determine if user has provided arguments via the terminal
  if len(sys.argv) > 1:
    # Use arguments as the list of emails (skipping the script name itself)
    emails = sys.argv[1:]
  else:
    # Example emails (from here: https://haveibeenpwned.com/api/v3#TestAccounts).
    # TODO: File reading logic
    # Default to test accounts provided by the API documentation if no input is given
    emails = [
      'account-exists@hibp-integration-tests.com',
      'multiple-breaches@hibp-integration-tests.com',
      'not-active-and-active-breach@hibp-integration-tests.com',
      'not-active-breach@hibp-integration-tests.com',
      'unverified-breach@hibp-integration-tests.com'
    ]
    print('No emails provided as arguments. Using example emails.')
    print('Usage: `python hibp_notifier.py email1@example.com email2@example.com`')
    # TODO: ... Or file input

  # Execute the check and capture the raw data
  results = checker.check_emails(emails)
  # Visualise the findings in the console
  checker.print_report(results)

  # Save to JSON
  # Serialise the results to a file for later analysis or integration with other tools
  with open('breach_report.json', 'w') as f:
    json.dump(results, f, indent=2)
  print('\n📄 Full report saved to `breach_report.json`')

# Ensure the script only runs if called directly, rather than imported as a module
if __name__ == '__main__':
  main()