import argparse              # Imports argparse for handling command‑line arguments
import whois                 # Imports the python‑whois library for WHOIS lookups
import dns.resolver          # Imports dnspython's resolver for DNS queries
from pprint import pprint

# ... Also an exercise in literate programming...

def get_whois(domain):
  try:
    w = whois.whois(domain)  # Performs a WHOIS lookup on the provided domain
    return w                 # Returns the WHOIS data object
  except Exception as e:
    return f'WHOIS lookup failed: {e}'  # Returns an error message if lookup fails
  
def get_dns_records(domain):
  # A: Maps a domain name to an IPv4 address.
  # AAAA: Maps a domain name to an IPv6 address.
  # MX: Specifies the mail servers responsible for receiving e‑mail for the domain.
  # NS: Lists the authoritative name servers that hold the domain’s DNS zone.
  # TXT: Holds arbitrary text data, often used for SPF, DKIM, DMARC, and other verification records.
  record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']  # DNS record types to query
  results = {}                                     # Dictionary to store results

  for rtype in record_types:                       # Iterates through each DNS record type
    try:
      answers = dns.resolver.resolve(domain, rtype)  # Attempts to resolve the record type
      results[rtype] = [str(rdata) for rdata in answers]  # Converts each record to string
    except Exception as e:
      results[rtype] = []                           # If lookup fails, store an empty list
      results[f'{rtype}_error'] = str(e)            # Capture the error message
  
  return results                                    # Returns all DNS results

def print_output(domain, whois_data, dns_data):
  print('\n===== WHOIS DATA =====')   # Section header for WHOIS output
  pprint(whois_data)                  # Pretty-prints raw WHOIS data

  print('\n===== DNS RECORDS =====') # Section header for DNS output
  for rtype, records in dns_data.items():  # Iterates through DNS record results
    print(f'\n{rtype} Records:')           # Prints the record type being displayed
    if records:                            # If records exist, print each one
      for r in records:
        print(f'   - {r}')
    else:
      print('   (none found)')             # Indicates no records were found

def main():
  parser = argparse.ArgumentParser(description = 'Basic WHOIS + DNS Enumerator')
  # Creates a command‑line argument parser with a description

  parser.add_argument('domain', help='Domain to enumerate.')
  # Adds a required positional argument for the domain name

  args = parser.parse_args()               # Parses command‑line arguments

  whois_data = get_whois(args.domain)      # Retrieves WHOIS information
  dns_data = get_dns_records(args.domain)  # Retrieves DNS records

  print_output(args.domain, whois_data, dns_data)  # Prints all gathered information

if __name__ == '__main__':  # Ensures main() runs only when script is executed directly
  main()                    # Calls the main function
