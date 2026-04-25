'''
Port Scanner with Report Generation
Scans IPs and generates CSV/PDF reports
'''

# Import the standard socket library for low-level network interface communication
import socket
# Access system-specific parameters and functions, such as command-line arguments
import sys
# Provides the ability to create, manipulate, and validate IPv4 and IPv6 addresses
import ipaddress  # Standard library for IP manipulation
# Import type hinting markers to improve code readability and static analysis
from typing import List, Dict, Optional
# Used for generating timestamps within the report metadata
from datetime import datetime
# Facilitates concurrent execution using a pool of threads to speed up the scanning process
from concurrent.futures import ThreadPoolExecutor, as_completed
# prevent To conditions race (to prevent race conditions)
import threading
# Facilitates the reading and writing of tabular data in Comma Separated Values format
import csv
# For stealth measures
import random
import time
# To allow undecorated function calls
from functools import wraps

# Attempt to load the PDF generation library; handle the error gracefully if it is missing
try:
  from fpdf import FPDF
except ImportError:
  print('⚠️  FPDF not installed. Install with: `pip install fpdf`')
  print('CSV report will still be generated.')

# Constants
NUM_PARALLEL_WORKERS = 20
# De-botifying jitter
JITTER_MIN = 0.1
JITTER_MAX = 0.5
# Backoff after so many failures
BACKOFF_THRESH = 10
# Backoff randomly for a (min, max) range of seconds
BACKOFF_MIN_WAIT = 15
BACKOFF_MAX_WAIT = 30
# Timeout values in seconds for scouting and full scans
SCOUTING_TIMEOUT = 0.5
SCAN_TIMEOUT = 1

# Create a global lock object for synchronising threads
# This ensures that our streak counter doesn't suffer from race conditions
scanner_lock = threading.Lock()

# Stealth measures
def adaptive_timing(func):
  '''
  A decorator to implement Jitter and Adaptive Back-off.
  This ensures the traffic profile looks less robotic and responds to throttling.
  '''
  @wraps(func) # Enables .__wrapped__
  def wrapper(self, *args, **kwargs):
    # Introduce 'Jitter' (0.1s to 0.5s) to vary the request cadence
    time.sleep(random.uniform(JITTER_MIN, JITTER_MAX))
    
    # Adaptive Timing Logic
    # Need a lock here to make this thread-safe
    # Only one thread should check/increment the streak at a time
    with scanner_lock:
      # If the scanner has hit too many consecutive timeouts, pause for a random duration between 15 and 30 seconds to let the network cool down
      if getattr(self, 'error_streak', 0) > BACKOFF_THRESH:
        # Calculate a random sleep interval to make the back-off period less predictable
        wait_time = random.randint(BACKOFF_MIN_WAIT, BACKOFF_MAX_WAIT)
        print(f'\n⚠️  Possible throttling detected (Error streak: {self.error_streak}). Backing off for {wait_time}s...')
        # Waiting while holding the lock is deliberate - it is effectively a global cool-down (extra stealth)
        time.sleep(wait_time)
        # Reset the streak counter to allow the scanner to resume with a fresh state
        self.error_streak = 0
        # We return here or skip the scan to prevent immediate re-triggering
        return None # Abort this specific port scan attempt
      
    # Perform the actual task
    result = func(self, *args, **kwargs)
    
    # Re-acquire the lock to safely update the shared state
    with scanner_lock:
      # If the result is a dictionary, it's an 'Open' port
      if isinstance(result, dict):
        self.error_streak = 0
      
      # If the result is 'BLOCKED', increment the streak (this is the stealth trigger)
      elif result == 'BLOCKED':
        self.error_streak = getattr(self, 'error_streak', 0) + 1
      
      # If the result is 'CLOSED', we do nothing to the streak. 
      # The host responded, so we aren't necessarily being throttled.
      elif result == 'CLOSED':
        pass 

    # Return only the dictionary (or None) to keep the rest of the script compatible
    return result if isinstance(result, dict) else None
  return wrapper

class PortScanner:
  # Common ports and services
  # A dictionary mapping port numbers to their commonly recognised service names
  COMMON_PORTS = {
    20: 'FTP Data',
    21: 'FTP Control',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    67: 'DHCP Server',
    68: 'DHCP Client',
    80: 'HTTP',
    110: 'POP3',
    123: 'NTP',
    143: 'IMAP',
    161: 'SNMP',
    389: 'LDAP',
    443: 'HTTPS',
    445: 'SMB',
    465: 'SMTPS',
    587: 'SMTP Submission',
    636: 'LDAPS',
    993: 'IMAPS',
    995: 'POP3S',
    1883: 'MQTT',
    2049: 'NFS',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    6379: 'Redis',
    8080: 'HTTP Proxy',
    8443: 'HTTPS Alt',
    9000: 'Portainer',
    9090: 'Prometheus',
    27017: 'MongoDB'
  }

  # Initialise the scanner with a custom timeout for connection attempts
  def __init__(self, timeout: int = SCAN_TIMEOUT):
    self.timeout = timeout
    self.results = []
    # Track the state of failures for the adaptive timing decorator
    self.error_streak = 0

  @adaptive_timing
  def scan_port(self, ip: str, port: int) -> Optional[Dict]:
    '''Scan a single port with timing logic applied via the decorator.'''
    try:
      # Establish a standard Internet stream socket (TCP)
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      # Set the maximum duration to wait for a response before giving up
      sock.settimeout(self.timeout)
      # Attempt to connect; connect_ex returns an error code instead of raising an exception
      result = sock.connect_ex((ip, port))
      # Close the socket to release system resources immediately
      sock.close()

      # A result of 0 signifies a successful connection (the port is open)
      if result == 0:
        service = self.COMMON_PORTS.get(port, 'Unknown')
        return {
          'ip': ip,
          'port': port,
          'status': 'Open',
          'service': service
        }
      
      # Check specific error codes if connect_ex didn't return 0
      # 111 is usually Connection Refused (Linux), 10061 (Windows)
      if result in (111, 10061):
        # This is a 'Closed' port - the host is there, but nothing is listening
        return 'CLOSED'

    except socket.timeout:
      # This is a 'Blocked/Filtered' port - a firewall likely dropped the packet
      # We return a specific marker or simply None, but the decorator 
      # should ideally only track THESE as errors.
      return 'BLOCKED'
    except socket.error:
      return 'BLOCKED'
    finally:
      # Safety check: only call close if the socket was actually created
      if sock:
        sock.close()
    return 'BLOCKED'

  def scan_host(self, ip: str, ports: List[int] = None) -> List[Dict]:
    '''Standard host scan, now benefitting from the decorated port scan.'''
    if ports is None:
      # Scan common ports
      # If no specific ports are provided, default to the predefined common service ports
      ports = list(self.COMMON_PORTS.keys())

    # --- SCOUT CHECK ---
    # We check one very common port (e.g., 80) first.
    # Note: We bypass the decorator here to avoid incrementing the streak 
    # for a host that might just have port 80 closed but others open.
    # We just want to see if we get a 'CLOSED' (Refused) vs 'BLOCKED' (Timeout).
    
    print(f'Checking if {ip} is alive...')
    # Scout a few common ports to be sure
    # 80 (Web), 443 (SSL), 22 (SSH), 445 (Windows SMB)
    scout_ports = [80, 443, 22, 445]
    is_alive = False

    # Save original timeout to restore it later
    original_timeout = self.timeout

    # FAST SCOUT: Set a very short timeout for the scout (e.g., 0.5s)
    # This speeds up skipping dead hosts significantly.
    self.timeout = SCOUTING_TIMEOUT
    
    # Simple check: If we get 'Open' OR 'Closed' (Refused), the host is alive.
    # If we get 'Blocked' (Timeout), we assume the host is down/filtered.
    for p in scout_ports:
      # Use the undecorated function (.__wrapped__) for scouting
      # So that it doesn't trip the global throttling back-off.
      status = self.scan_port.__wrapped__(self, ip, p) # Bypass the decorator - needs the explicit `self` too
      # If any port is Open (dict) or Closed (str 'CLOSED'), the host is UP
      if isinstance(status, dict) or status == 'CLOSED':
        is_alive = True
        break # Success! Stop scouting and start the real scan
    
    # Restore the original timeout for the actual full scan
    self.timeout = original_timeout

    if not is_alive:
      print(f'⏩ Skipping {ip} (No response on scout port(s)).')
      return []

    # --- FULL SCAN ---
    # If the host is alive, proceed with the full multi-threaded scan
    open_ports = []
    print(f'Scanning {ip} ...')

    # Use a thread pool to dispatch multiple connection requests simultaneously
    # A lower threadpool worker count complements the jitter logic
    with ThreadPoolExecutor(max_workers = NUM_PARALLEL_WORKERS) as executor:
      # Map the scan function across the list of ports to be checked
      futures = {
        executor.submit(self.scan_port, ip, port): port
        for port in ports
      }

      # Process results as soon as each individual thread completes its task
      for future in as_completed(futures):
        result = future.result()
        if result:
          open_ports.append(result)

    # Reset the streak at the end of the host scan so the next host 
    # starts with a clean slate.
    with scanner_lock:
      self.error_streak = 0

    return open_ports
  
  def scan_range(self, start_ip: str, end_ip: str, ports: List[int] = None) -> List[Dict]:
    '''Scan a range of IPs using a randomised order'''
    all_results = []

    try:
      # Determine the actual end IP
      # Logic: If end_ip is just a number (e.g., '10'), build it from start_ip's prefix
      if end_ip.isdigit():
        # Split the starting IP to retrieve the first three octets
        base_parts = start_ip.split('.')
        # Replace the final octet with the provided shorthand number
        base_parts[-1] = end_ip
        end_ip_str = '.'.join(base_parts)
      else:
        end_ip_str = end_ip

      # Leverage ipaddress to calculate the range sequence
      # Convert string representations into formal IPv4Address objects for comparison and iteration
      start_addr = ipaddress.IPv4Address(start_ip)
      end_addr = ipaddress.IPv4Address(end_ip_str)

      # Ensure range is valid (start <= end)
      # Prevent the logic from executing if the range is logically reversed
      if start_addr > end_addr:
        print(f'❌ Error: Start IP {start_addr} is greater than End IP {end_addr}')
        return []
      
      # Generate the full list of IP strings in the range
      ip_pool = [
        str(ipaddress.IPv4Address(ip_int)) 
        for ip_int in range(int(start_addr), int(end_addr) + 1)
      ]

      # Shuffle the list so the scan pattern is non-linear
      random.shuffle(ip_pool)

      # Iterate through the randomised pool
      for ip_str in ip_pool:
        results = self.scan_host(ip_str, ports)
        all_results.extend(results)

    except ValueError as e:
      print(f'❌ Invalid IP Format: {e}')
    
    return all_results

  def generate_csv_report(self, results: List[Dict], filename: str = 'port_scan_report.csv'):
    '''Generate CSV report'''
    # Open a file handler with 'newline' set to empty to prevent extra spacing on Windows systems
    with open(filename, 'w', newline='') as csvfile:
      fieldnames = ['IP', 'Port', 'Status', 'Service']
      writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

      # Write the header row based on the fieldnames defined above
      writer.writeheader()
      # Iterate through the results and write each entry as a new row
      for result in results:
        writer.writerow({
          'IP': result['ip'],
          'Port': result['port'],
          'Status': result['status'],
          'Service': result['service']
        })

    print(f'\n📄 CSV report saved to {filename}')

  def generate_pdf_report(self, results: List[Dict], filename: str = 'port_scan_report.pdf'):
    '''Generate PDF report'''
    try:
      # Initialise the FPDF object and add a starting page
      pdf = FPDF()
      pdf.add_page()
      # Configure the font for the main document heading
      pdf.set_font('Arial', 'B', 16)
      
      title = 'Port Scan Report'
      # Render the title text centred at the top of the page
      pdf.cell(0, 10, title, ln=True, align='C')
      
      # Configure a smaller font for the metadata section
      pdf.set_font('Arial', '', 10)
      # Output the generation date and the count of discovered open ports
      pdf.cell(0, 10, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', ln=True, align='C')
      pdf.cell(0, 10, f'Total open ports found: {len(results)}', ln=True, align='C')
      
      # Add a vertical gap before starting the table
      pdf.ln(10)
      
      # Table header
      # Set bold font for the table column headers
      pdf.set_font('Arial', 'B', 10)
      pdf.cell(40, 10, 'IP Address', border=1)
      pdf.cell(30, 10, 'Port', border=1)
      pdf.cell(40, 10, 'Status', border=1)
      pdf.cell(50, 10, 'Service', border=1)
      pdf.ln()
      
      # Table data
      # Revert to standard font weight for the actual data entries
      pdf.set_font('Arial', '', 10)
      for result in results:
        pdf.cell(40, 10, result['ip'], border=1)
        pdf.cell(30, 10, str(result['port']), border=1)
        pdf.cell(40, 10, result['status'], border=1)
        pdf.cell(50, 10, result['service'], border=1)
        pdf.ln()
      
      # Finalise the document and save it to the specified path
      pdf.output(filename)
      print(f'📄 PDF report saved to {filename}')

    except Exception as e:
      print(f'❌ Error generating PDF: {e}')

# Driver
# The main entry point for the script execution
def main():
  # Instantiate the scanner with a 1-second connection timeout
  scanner = PortScanner(timeout=1)

  # Example usage
  # Check if a target argument was passed via the command line
  if len(sys.argv) > 1:
    target = sys.argv[1].strip()

    # CIDR Subnet Logic (e.g., 192.168.1.0/24)
    # Detect if the user provided a network range in CIDR notation
    if '/' in target:
      try:
        # Create a network object; 'strict=False' allows using an IP that isn't the network address
        network = ipaddress.ip_network(target, strict=False)
        # Use the first and last address of the subnet to feed scan_range
        results = scanner.scan_range(str(network[0]), str(network[-1]))
      except ValueError as e:
        print(f'❌ Invalid CIDR format: {e}')
        sys.exit(1)

    # Existing Range Logic (e.g., 192.168.1.1-10)
    # Detect if the user provided a hyphenated range of IPs
    elif '-' in target:
      targets = target.split('-')
      # Execute the range scan using the split start and end values
      results = scanner.scan_range(targets[0].strip(), targets[1].strip())
    
    # Single Host Logic
    # Default to scanning a single host if no range or subnet notation is found
    else:
      results = scanner.scan_host(target)
  
  else:
    # Example: Scan localhost
    # Display help information and usage examples if no arguments are provided
    print('-' * 50)
    print('⚡ PORT SCANNER HELP & USAGE ⚡')
    print('-' * 50)
    print('Usage:   python port_scanner.py <target>')
    print('\nExamples:')
    print('  Single IP:   python port_scanner.py 192.168.1.1')
    print('  Shorthand:   python port_scanner.py 192.168.1.1-10')
    print('  Full Range:  python port_scanner.py 192.168.1.250-192.168.2.5')
    print('  Subnet Mask: python port_scanner.py 192.168.1.0/24')
    print('-' * 50)
    print('\nNo target specified. Defaulting to Localhost (127.0.0.1)...')

    # Fallback to scanning the local loopback address
    results = scanner.scan_host('127.0.0.1')

  # Print results
  # Output the findings to the terminal in a human-readable format
  print('\n' + '='*80)
  print('SCAN RESULTS')
  print('=' * 80)
  
  if results:
    for result in results:
      print(f'✅ {result["ip"]}:{result["port"]} - {result["service"]}')
  else:
    print('No open ports found.')
  
  # Generate reports
  # If any open ports were identified, trigger the file generation methods
  if results:
    scanner.generate_csv_report(results)
    scanner.generate_pdf_report(results)
  
  print('=' * 80)

# Boilerplate to ensure the main function only runs when the script is executed directly
if __name__ == '__main__':
  main()
