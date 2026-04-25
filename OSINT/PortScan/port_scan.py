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
from typing import List, Dict
# Used for generating timestamps within the report metadata
from datetime import datetime
# Facilitates concurrent execution using a pool of threads to speed up the scanning process
from concurrent.futures import ThreadPoolExecutor, as_completed
# Facilitates the reading and writing of tabular data in Comma Separated Values format
import csv

# Attempt to load the PDF generation library; handle the error gracefully if it is missing
try:
  from fpdf import FPDF
except ImportError:
  print('⚠️  FPDF not installed. Install with: `pip install fpdf`')
  print('CSV report will still be generated.')

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
  def __init__(self, timeout: int = 1):
    self.timeout = timeout
    self.results = []

  def scan_port(self, ip:str, port: int) -> Dict:
    '''Scan a single port'''
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
    except socket.error:
      pass
    return None

  def scan_host(self, ip: str, ports: List[int] = None) -> List[Dict]:
    '''Scan all ports for a host'''
    if ports is None:
      # Scan common ports
      # If no specific ports are provided, default to the predefined common service ports
      ports = list(self.COMMON_PORTS.keys())

    open_ports = []
    print(f'Scanning {ip} ...')

    # Use a thread pool to dispatch multiple connection requests simultaneously
    with ThreadPoolExecutor(max_workers = 50) as executor:
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

    return open_ports
  
  def scan_range(self, start_ip: str, end_ip: str, ports: List[int] = None) -> List[Dict]:
    '''Scan a range of IPs'''
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
            print(f"❌ Error: Start IP {start_addr} is greater than End IP {end_addr}")
            return []

        # Iterate through the range
        # Treat the IP addresses as integers to allow for simple mathematical iteration
        for ip_int in range(int(start_addr), int(end_addr) + 1):
            # Convert the integer back to a standard string-based IP format
            ip_str = str(ipaddress.IPv4Address(ip_int))
            results = self.scan_host(ip_str, ports)
            all_results.extend(results)

    except ValueError as e:
        print(f"❌ Invalid IP Format: {e}")
    
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


'''
FUTURE WORK

A. Randomise the Scan Order
Instead of scanning .1, .2, .3..., shuffle the list of IPs. Firewalls look for sequential hits.

B. Implement Jitter and Latency
Scanning 50 ports simultaneously is efficient but loud. Adding a small, random delay (jitter) between requests makes the traffic look more human.

C. Adaptive Timing
Several Connection Refused or Timeout errors in a row => the firewall has likely throttled you.
'''

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
        print(f"❌ Invalid CIDR format: {e}")
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