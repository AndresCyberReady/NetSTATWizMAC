#CyberReady

"""
NetStatWiz - Network Statistics Wizard
A tool to analyze network connections, visualize IP locations on a map,
and display ports and services in tables.
"""

import subprocess
import re
import json
import socket
import urllib.request
import urllib.error
import urllib.parse
import ssl
import os
import platform
from collections import defaultdict
from typing import List, Dict, Tuple, Optional
import time

try:
    import folium  # type: ignore
    from folium import plugins  # type: ignore
    FOLIUM_AVAILABLE = True
except ImportError:
    FOLIUM_AVAILABLE = False

try:
    import pandas as pd  # type: ignore
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False


# Common port to service mappings
PORT_SERVICES = {
    # File Transfer
    20: "FTP Data", 21: "FTP", 22: "SSH", 69: "TFTP", 989: "FTPS Data", 990: "FTPS",
    
    # Remote Access
    23: "Telnet", 3389: "RDP", 5900: "VNC", 5901: "VNC-1", 5902: "VNC-2",
    5800: "VNC-HTTP", 5801: "VNC-HTTP-1", 512: "Rexec", 513: "Rlogin",
    
    # Email
    25: "SMTP", 110: "POP3", 143: "IMAP", 465: "SMTPS", 587: "SMTP Submission",
    993: "IMAPS", 995: "POP3S",
    
    # Web Services
    80: "HTTP", 443: "HTTPS", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    8000: "HTTP-Alt", 8008: "HTTP-Alt-2", 8888: "HTTP-Alt-3",
    
    # DNS & Network
    53: "DNS", 67: "DHCP", 68: "DHCP Client", 123: "NTP", 161: "SNMP", 162: "SNMP Trap",
    
    # Database
    1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL", 1521: "Oracle",
    27017: "MongoDB", 6379: "Redis", 5984: "CouchDB", 9200: "Elasticsearch",
    
    # File Sharing
    445: "SMB", 139: "NetBIOS", 2049: "NFS", 111: "RPC",
    
    # Messaging & Chat
    5222: "XMPP", 5223: "XMPP-SSL", 6667: "IRC", 6668: "IRC-Alt",
    
    # Remote Management
    5985: "WinRM HTTP", 5986: "WinRM HTTPS", 623: "IPMI", 16992: "Intel AMT",
    
    # Gaming
    27015: "Steam", 25565: "Minecraft", 7777: "Unreal Tournament",
    
    # Development & Testing
    3000: "Node.js", 9000: "SonarQube",
    
    # Other Services
    389: "LDAP", 514: "Syslog", 636: "LDAPS", 873: "Rsync",
    1434: "MSSQL Browser", 1527: "Apache Derby", 2375: "Docker", 2376: "Docker TLS",
    5000: "UPnP/Flask", 5353: "mDNS", 548: "AFP", 631: "IPP",
    1723: "PPTP", 1194: "OpenVPN", 500: "IKE", 4500: "IPSec NAT-T",
    8000: "HTTP-Alt/Django",
    
    # ⚠️ SECURITY ALERT - Common Malware/Trojan Ports
    # Remote Access Trojans (RATs) & Backdoors
    31337: "Back Orifice", 12345: "NetBus", 12346: "NetBus Alt", 20034: "NetBus Pro",
    54320: "Back Orifice 2000", 54321: "Back Orifice 2000", 40421: "Masters Paradise",
    40422: "Masters Paradise", 40423: "Masters Paradise", 40426: "Masters Paradise",
    31785: "Hack-a-Tack", 31787: "Hack-a-Tack", 31788: "Hack-a-Tack", 31789: "Hack-a-Tack",
    31791: "Hack-a-Tack", 31792: "Hack-a-Tack", 60008: "PhatBot/Agobot",
    
    # Common Trojan Ports
    1243: "SubSeven", 6711: "SubSeven", 6712: "SubSeven", 6713: "SubSeven",
    6776: "SubSeven", 1245: "VooDoo Doll", 555: "Phase Zero", 9989: "iNi-Killer",
    10000: "Webmin/Control", 10001: "SCADA", 10008: "Octopus", 10050: "Zabbix Agent",
    10051: "Zabbix Server", 10168: "Ambush", 10666: "Ambush", 10667: "VideoAddon",
    11000: "Senna Spy", 11223: "Progenic", 12076: "Gjamer", 12223: "Hack'99 KeyLogger",
    12361: "Whack-a-Mole", 12362: "Whack-a-Mole", 16969: "Priority", 20000: "Millennium",
    20001: "Millennium", 21544: "GirlFriend", 22222: "Prosiak", 23456: "Evil FTP",
    26274: "Delta Source", 27374: "SubSeven", 30100: "NetSphere", 30101: "NetSphere",
    30102: "NetSphere", 30103: "NetSphere", 30303: "Socket23", 30999: "Kuang",
    31338: "Deep BO", 31339: "NetSpy DK", 31666: "BOWhack", 33333: "Prosiak",
    34324: "BigGluck", 40412: "The Spy", 40421: "Masters Paradise", 40422: "Masters Paradise",
    40423: "Masters Paradise", 40426: "Masters Paradise", 43210: "Hackers Paradise",
    44444: "Prosiak", 47262: "Delta", 50505: "Sockets de Troie", 50766: "Fore",
    53001: "Remote Windows Shutdown", 54321: "School Bus", 61466: "Telecommando",
    65000: "Devil", 69123: "ICQ Revenge",
    
    # Exploit Frameworks & Penetration Testing Tools
    4444: "Metasploit", 55553: "Metasploit", 45678: "EBA", 47808: "Backdoor",
    49664: "Backdoor", 49665: "Backdoor", 49666: "Backdoor", 49667: "Backdoor",
    49668: "Backdoor", 49669: "Backdoor", 49670: "Backdoor",
    
    # Cryptocurrency Mining & Botnet C2
    3333: "Monero Mining", 4444: "Monero Mining", 7777: "Monero Mining",
    9999: "Distributed.net", 14444: "Bitcoin", 8332: "Bitcoin RPC", 8333: "Bitcoin",
    9332: "Litecoin RPC", 9333: "Litecoin", 22565: "VNC (Suspicious)",
    
    # Data Exfiltration & Unauthorized Services
    6666: "IRC (Suspicious)", 6667: "IRC (Suspicious)", 6668: "IRC (Suspicious)",
    6669: "IRC (Suspicious)", 7000: "IRC (Suspicious)", 7001: "IRC (Suspicious)",
    8081: "HTTP Proxy (Suspicious)", 8118: "Privoxy", 8123: "Polipo",
    9050: "Tor SOCKS", 9051: "Tor Control", 9150: "Tor Browser",
    
    # Unencrypted Database Access (Security Risk)
    1433: "MSSQL (Unencrypted)", 3306: "MySQL (Unencrypted)", 5432: "PostgreSQL (Unencrypted)",
    27017: "MongoDB (Unencrypted)", 6379: "Redis (Unencrypted)",
    
    # Suspicious Remote Access
    4899: "Radmin", 5500: "VNC (Suspicious)", 5501: "VNC (Suspicious)",
    5800: "VNC-HTTP (Suspicious)", 5900: "VNC (Suspicious)", 5901: "VNC (Suspicious)",
    5902: "VNC (Suspicious)", 5903: "VNC (Suspicious)", 5904: "VNC (Suspicious)",
    5905: "VNC (Suspicious)", 5906: "VNC (Suspicious)", 5907: "VNC (Suspicious)",
    5908: "VNC (Suspicious)", 5909: "VNC (Suspicious)", 5910: "VNC (Suspicious)",
    
    # File Transfer (Unencrypted - Security Risk)
    21: "FTP (Unencrypted)", 69: "TFTP (Unencrypted)", 115: "SFTP (Unencrypted)",
    
    # Unencrypted Remote Access (High Risk)
    23: "Telnet (Unencrypted)", 512: "Rexec (Unencrypted)", 513: "Rlogin (Unencrypted)",
    514: "Rsh (Unencrypted)", 515: "LPD (Unencrypted)",
    
    # Other Suspicious Ports
    81: "HTTP (Non-Standard)", 82: "HTTP (Non-Standard)", 83: "HTTP (Non-Standard)",
    84: "HTTP (Non-Standard)", 85: "HTTP (Non-Standard)", 86: "HTTP (Non-Standard)",
    87: "HTTP (Non-Standard)", 88: "HTTP (Non-Standard)", 89: "HTTP (Non-Standard)",
    8001: "HTTP (Non-Standard)", 8002: "HTTP (Non-Standard)", 8003: "HTTP (Non-Standard)",
    8004: "HTTP (Non-Standard)", 8005: "HTTP (Non-Standard)", 8006: "HTTP (Non-Standard)",
    8007: "HTTP (Non-Standard)", 8009: "HTTP (Non-Standard)", 8010: "HTTP (Non-Standard)",
    8880: "HTTP (Non-Standard)", 8881: "HTTP (Non-Standard)", 8882: "HTTP (Non-Standard)",
    8883: "HTTP (Non-Standard)", 8884: "HTTP (Non-Standard)", 8885: "HTTP (Non-Standard)",
    8886: "HTTP (Non-Standard)", 8887: "HTTP (Non-Standard)", 8889: "HTTP (Non-Standard)",
    8890: "HTTP (Non-Standard)", 9001: "HTTP (Non-Standard)", 9002: "HTTP (Non-Standard)",
    9003: "HTTP (Non-Standard)", 9004: "HTTP (Non-Standard)", 9005: "HTTP (Non-Standard)",
    9006: "HTTP (Non-Standard)", 9007: "HTTP (Non-Standard)", 9008: "HTTP (Non-Standard)",
    9009: "HTTP (Non-Standard)", 9010: "HTTP (Non-Standard)",
    
    # Web Shells & Backdoors
    888: "HTTP (Suspicious)", 999: "HTTP (Suspicious)", 1337: "HTTP (Suspicious)",
    1338: "HTTP (Suspicious)", 1339: "HTTP (Suspicious)", 1340: "HTTP (Suspicious)",
    1341: "HTTP (Suspicious)", 1342: "HTTP (Suspicious)", 1343: "HTTP (Suspicious)",
    1344: "HTTP (Suspicious)", 1345: "HTTP (Suspicious)", 1346: "HTTP (Suspicious)",
    1347: "HTTP (Suspicious)", 1348: "HTTP (Suspicious)", 1349: "HTTP (Suspicious)",
    1350: "HTTP (Suspicious)", 1351: "HTTP (Suspicious)", 1352: "HTTP (Suspicious)",
    1353: "HTTP (Suspicious)", 1354: "HTTP (Suspicious)", 1355: "HTTP (Suspicious)",
    1356: "HTTP (Suspicious)", 1357: "HTTP (Suspicious)", 1358: "HTTP (Suspicious)",
    1359: "HTTP (Suspicious)", 1360: "HTTP (Suspicious)",
    
    # Command & Control (C2) Communication (Non-Standard Ports Only)
    # Note: Standard ports 80/443 are legitimate web traffic and not flagged here
    53: "DNS (Potential C2 - if unexpected)", 8080: "HTTP-Proxy (Potential C2)",
    8443: "HTTPS-Alt (Potential C2)"
}


# IP Abuse API Configuration
# Insert your API key here (e.g., from AbuseIPDB, VirusTotal, etc.)
IP_ABUSE_API_KEY = "#"  #: Insert your IP Abuse API key here
IP_ABUSE_API_URL = "https://api.abuseipdb.com/api/v2/check"  # AbuseIPDB API endpoint

class NetStatWiz:
    def __init__(self):
        self.connections = []
        self.ip_locations = {}
        self.ip_abuse_data = {}  # Store abuse check results
        self.port_services = defaultdict(list)
        self.is_macos = platform.system() == 'Darwin'
        
    def get_service_name(self, port: int) -> str:
        """Get service name for a given port."""
        return PORT_SERVICES.get(port, "Unknown")
    
    def run_netstat(self) -> List[str]:
        """Run netstat command and return output lines (supports Windows and macOS)."""
        try:
            # Run netstat with -an flags (all connections, numeric addresses)
            # Works on both Windows and macOS
            result = subprocess.run(
                ['netstat', '-an'],
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.stdout.split('\n')
        except subprocess.TimeoutExpired:
            print("Error: netstat command timed out")
            return []
        except Exception as e:
            print(f"Error running netstat: {e}")
            return []
    
    def parse_address_port(self, addr_str: str) -> Tuple[Optional[str], Optional[int]]:
        """Parse address:port or address.port format (supports Windows and macOS)."""
        if not addr_str or addr_str == '*.*' or addr_str == '*':
            return None, None
        
        # macOS format: IP.PORT (e.g., 192.168.1.1.80) or *.PORT (e.g., *.80)
        if '.' in addr_str and ':' not in addr_str:
            # Check if it's *.PORT format
            if addr_str.startswith('*.'):
                try:
                    port = int(addr_str[2:])
                    return '*', port
                except ValueError:
                    return None, None
            # Otherwise it's IP.PORT format
            parts = addr_str.rsplit('.', 1)
            if len(parts) == 2:
                ip = parts[0]
                try:
                    port = int(parts[1])
                    return ip, port
                except ValueError:
                    return None, None
        
        # Windows format: IP:PORT (e.g., 192.168.1.1:80) or [IPv6]:PORT
        if ':' in addr_str:
            # Handle IPv6 addresses in brackets: [::1]:80
            if addr_str.startswith('['):
                end_bracket = addr_str.find(']')
                if end_bracket != -1:
                    ip = addr_str[1:end_bracket]
                    try:
                        port = int(addr_str[end_bracket + 2:])
                        return ip, port
                    except ValueError:
                        return None, None
            else:
                # IPv4 format: IP:PORT
                parts = addr_str.rsplit(':', 1)
                if len(parts) == 2:
                    ip = parts[0]
                    try:
                        port = int(parts[1])
                        return ip, port
                    except ValueError:
                        return None, None
        
        return None, None
    
    def parse_netstat_output(self, lines: List[str]) -> List[Dict]:
        """Parse netstat output and extract connection information (supports Windows and macOS)."""
        connections = []
        
        if self.is_macos:
            # macOS format: tcp4       0      0  192.168.1.1.80         *.*                    LISTEN
            # Pattern: protocol, recv-q, send-q, local-address, foreign-address, state
            pattern = re.compile(
                r'^\s*(tcp4?6?|udp4?6?)\s+'
                r'\d+\s+'  # Recv-Q
                r'\d+\s+'  # Send-Q
                r'([^\s]+)\s+'  # Local address (IP.PORT or *.PORT)
                r'([^\s]+)\s+'  # Foreign address (IP.PORT or *.*)
                r'(\w+).*'  # State (may have trailing whitespace)
            )
        else:
            # Windows format: TCP    0.0.0.0:80             0.0.0.0:0              LISTENING
            pattern = re.compile(
                r'^\s*(TCP|UDP)\s+'
                r'([^\s]+)\s+'  # Local address (IP:PORT)
                r'([^\s]+)\s+'  # Remote address (IP:PORT)
                r'(\w+)'  # State
            )
        
        for line in lines:
            match = pattern.match(line)
            if match:
                if self.is_macos:
                    protocol, local_addr, remote_addr, state = match.groups()
                    local_ip, local_port = self.parse_address_port(local_addr)
                    remote_ip, remote_port = self.parse_address_port(remote_addr)
                else:
                    protocol, local_addr, remote_addr, state = match.groups()
                    local_ip, local_port = self.parse_address_port(local_addr)
                    remote_ip, remote_port = self.parse_address_port(remote_addr)
                
                # Skip if we couldn't parse addresses
                if not remote_ip or not remote_port:
                    continue
                
                # Skip localhost and private IPs for remote connections
                if remote_ip not in ['0.0.0.0', '127.0.0.1', '::', '::1']:
                    # Skip private IP ranges
                    if not self.is_private_ip(remote_ip):
                        connections.append({
                            'protocol': protocol.upper(),
                            'local_ip': local_ip or '0.0.0.0',
                            'local_port': local_port or 0,
                            'remote_ip': remote_ip,
                            'remote_port': remote_port,
                            'state': state
                        })
        
        return connections
    
    def is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range."""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            first = int(parts[0])
            second = int(parts[1])
            
            # Private IP ranges
            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
            if first == 127:
                return True
            return False
        except:
            return False
    
    def check_ip_abuse(self, ip: str) -> Optional[Dict]:
        """Check IP address against AbuseIPDB API for abuse reports."""
        if not IP_ABUSE_API_KEY:
            return None
        
        if ip in self.ip_abuse_data:
            return self.ip_abuse_data[ip]
        
        # Skip private IPs
        if self.is_private_ip(ip):
            return None
        
        # Rate limit: Be respectful with API calls
        time.sleep(2)  # AbuseIPDB allows 1000 requests per day for free tier
        
        try:
            # AbuseIPDB API v2 format - CHECK endpoint (GET request)
            # According to docs: https://docs.abuseipdb.com/#configuring-fail2ban
            # - IP address must be URL-encoded (especially for IPv6)
            # - Parameters: ipAddress (required), maxAgeInDays (optional, 1-365), verbose (optional flag)
            # - Headers: Key (API key), Accept: application/json
            
            # Build query parameters properly
            params = {
                'ipAddress': ip,  # Will be URL-encoded
                'maxAgeInDays': '90',
                'verbose': ''  # Flag parameter
            }
            
            # URL-encode the parameters (especially important for IPv6 addresses with colons)
            query_string = urllib.parse.urlencode(params)
            url = f"{IP_ABUSE_API_URL}?{query_string}"
            
            # Create request with API key in header (recommended method per docs)
            req = urllib.request.Request(url, method='GET')
            req.add_header('Key', IP_ABUSE_API_KEY)
            req.add_header('Accept', 'application/json')
            
            # Create SSL context that works on macOS
            # On macOS, sometimes certificates aren't found, so we create an unverified context
            # This is acceptable for API calls where we're validating the API key
            ssl_context = ssl._create_unverified_context()
            
            with urllib.request.urlopen(req, timeout=10, context=ssl_context) as response:
                data = json.loads(response.read().decode())
                
                if data.get('data'):
                    abuse_info = data['data']
                    abuse_result = {
                        'ip': ip,
                        'is_public': abuse_info.get('isPublic', False),
                        'ip_version': abuse_info.get('ipVersion', 4),
                        'is_whitelisted': abuse_info.get('isWhitelisted', False),
                        'abuse_confidence_score': abuse_info.get('abuseConfidenceScore', 0),
                        'usage_type': abuse_info.get('usageType', 'Unknown'),
                        'isp': abuse_info.get('isp', 'Unknown'),
                        'domain': abuse_info.get('domain', 'Unknown'),
                        'hostnames': abuse_info.get('hostnames', []),
                        'is_tor': abuse_info.get('isTor', False),
                        'total_reports': abuse_info.get('totalReports', 0),
                        'num_distinct_users': abuse_info.get('numDistinctUsers', 0),
                        'last_reported_at': abuse_info.get('lastReportedAt', 'Never'),
                        'country_code': abuse_info.get('countryCode', 'Unknown'),
                        'country_name': abuse_info.get('countryName', 'Unknown')
                    }
                    self.ip_abuse_data[ip] = abuse_result
                    return abuse_result
                else:
                    return None
        except urllib.error.HTTPError as e:
            # Handle HTTP errors according to AbuseIPDB API documentation
            if e.code == 401:
                print(f"  ⚠ API Key error for {ip}: Invalid or missing API key")
            elif e.code == 429:
                # Rate limit exceeded - check headers for details
                retry_after = e.headers.get('Retry-After', 'Unknown')
                limit = e.headers.get('X-RateLimit-Limit', 'Unknown')
                remaining = e.headers.get('X-RateLimit-Remaining', '0')
                reset = e.headers.get('X-RateLimit-Reset', 'Unknown')
                print(f"  ⚠ Rate limit exceeded for {ip}: Too many requests")
                print(f"     Daily limit: {limit}, Remaining: {remaining}, Reset: {reset}, Retry after: {retry_after} seconds")
            elif e.code == 422:
                # Validation error
                try:
                    error_body = e.read().decode()
                    error_data = json.loads(error_body)
                    error_detail = error_data.get('errors', [{}])[0].get('detail', 'Unknown error')
                    print(f"  ⚠ Validation error for {ip}: {error_detail}")
                except:
                    print(f"  ⚠ HTTP 422 Validation error for {ip}")
            else:
                print(f"  ⚠ HTTP Error {e.code} checking abuse for {ip}")
            return None
        except Exception as e:
            print(f"  ⚠ Error checking abuse for {ip}: {e}")
            return None
    
    def get_ip_location(self, ip: str) -> Optional[Dict]:
        """Get geolocation information for an IP address using ip-api.com."""
        if ip in self.ip_locations:
            return self.ip_locations[ip]
        
        # Rate limit: ip-api.com allows 45 requests per minute
        time.sleep(1.5)  # Be respectful with API calls
        
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,isp,org,query"
            with urllib.request.urlopen(url, timeout=5) as response:
                data = json.loads(response.read().decode())
                
                if data.get('status') == 'success':
                    location = {
                        'ip': ip,
                        'country': data.get('country', 'Unknown'),
                        'region': data.get('regionName', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'latitude': data.get('lat', 0),
                        'longitude': data.get('lon', 0),
                        'isp': data.get('isp', 'Unknown'),
                        'org': data.get('org', 'Unknown')
                    }
                    self.ip_locations[ip] = location
                    return location
                else:
                    print(f"Failed to get location for {ip}: {data.get('message', 'Unknown error')}")
                    return None
        except urllib.error.HTTPError as e:
            print(f"HTTP Error for {ip}: {e}")
            return None
        except Exception as e:
            print(f"Error getting location for {ip}: {e}")
            return None
    
    def analyze_connections(self):
        """Main analysis function."""
        print("Running netstat...")
        netstat_output = self.run_netstat()
        
        print("Parsing connections...")
        self.connections = self.parse_netstat_output(netstat_output)
        print(f"Found {len(self.connections)} external connections")
        
        if not self.connections:
            print("No external connections found.")
            return
        
        print("\nGetting IP geolocation data (this may take a while)...")
        unique_ips = set(conn['remote_ip'] for conn in self.connections)
        print(f"Found {len(unique_ips)} unique IP addresses")
        
        for i, ip in enumerate(unique_ips, 1):
            print(f"Processing IP {i}/{len(unique_ips)}: {ip}")
            self.get_ip_location(ip)
        
        # Check IPs for abuse if API key is configured
        if IP_ABUSE_API_KEY:
            print("\nChecking IPs against AbuseIPDB (this may take a while)...")
            for i, ip in enumerate(unique_ips, 1):
                print(f"Checking abuse for IP {i}/{len(unique_ips)}: {ip}")
                abuse_data = self.check_ip_abuse(ip)
                if abuse_data and abuse_data.get('abuse_confidence_score', 0) > 0:
                    score = abuse_data['abuse_confidence_score']
                    reports = abuse_data.get('total_reports', 0)
                    print(f"  ⚠️  Abuse detected! Score: {score}%, Reports: {reports}")
        else:
            print("\n⚠️  IP Abuse checking skipped (no API key configured)")
            print("   To enable abuse checking, add your AbuseIPDB API key to IP_ABUSE_API_KEY")
        
        # Organize by port and service
        for conn in self.connections:
            port = conn['remote_port']
            service = self.get_service_name(port)
            self.port_services[port].append({
                'ip': conn['remote_ip'],
                'service': service,
                'protocol': conn['protocol'],
                'state': conn['state']
            })
    
    def generate_map(self, output_file: str = "network_map.html"):
        """Generate an interactive map showing IP locations."""
        # Runtime check for folium (in case it was installed after script started)
        folium_available = FOLIUM_AVAILABLE
        if not folium_available:
            try:
                import folium  # type: ignore
                folium_available = True
            except ImportError:
                folium_available = False
        
        if not folium_available:
            print("\n" + "="*60)
            print("✗ CANNOT GENERATE MAP: folium is not installed")
            print("="*60)
            print("To install folium, run one of the following commands:")
            if self.is_macos:
                print("  pip3 install folium")
                print("  pip3 install -r requirements.txt")
            else:
                print("  pip install folium")
                print("  pip install -r requirements.txt")
            print("\nAfter installing, run the program again to generate the map.")
            print("="*60 + "\n")
            return
        
        # Import folium (it's available)
        import folium  # type: ignore
        
        print(f"  Checking IP locations... Found {len(self.ip_locations)} locations")
        if not self.ip_locations:
            print("  ⚠ No location data available for map generation")
            print("  Creating empty map file anyway...")
            # Still create an empty map file
            abs_output_file = os.path.abspath(output_file)
            try:
                m = folium.Map(location=[20, 0], zoom_start=2)
                m.save(abs_output_file)
                if os.path.exists(abs_output_file):
                    print(f"  ✓ Created empty map file at: {abs_output_file}")
                else:
                    print(f"  ✗ Failed to create map file")
            except Exception as e:
                print(f"  ✗ Error creating empty map: {e}")
            return
        
        try:
            # Get absolute path for output file
            abs_output_file = os.path.abspath(output_file)
            print(f"  Output file path: {abs_output_file}")
            
            # Create base map
            print("  Creating folium map...")
            try:
                m = folium.Map(location=[20, 0], zoom_start=2)
                print("  ✓ Map object created successfully")
            except Exception as e:
                print(f"  ✗ ERROR creating map object: {e}")
                import traceback
                traceback.print_exc()
                return
            
            markers_added = 0
            # Add markers for each IP location
            for ip, location in self.ip_locations.items():
                if location.get('latitude') and location.get('longitude') and location['latitude'] != 0 and location['longitude'] != 0:
                    # Count connections to this IP
                    conn_count = sum(1 for c in self.connections if c['remote_ip'] == ip)
                    
                    # Get abuse data if available
                    abuse_data = self.ip_abuse_data.get(ip, {})
                    abuse_score = abuse_data.get('abuse_confidence_score', 0)
                    total_reports = abuse_data.get('total_reports', 0)
                    is_tor = abuse_data.get('is_tor', False)
                    usage_type = abuse_data.get('usage_type', 'Unknown')
                    
                    # Create popup content with abuse information
                    popup_html = f"""
                    <div style="font-family: Arial; width: 250px;">
                        <h4>{ip}</h4>
                        <p><b>Location:</b> {location['city']}, {location['region']}, {location['country']}</p>
                        <p><b>ISP:</b> {location['isp']}</p>
                        <p><b>Organization:</b> {location['org']}</p>
                        <p><b>Connections:</b> {conn_count}</p>
                    """
                    
                    # Add abuse information if available
                    if IP_ABUSE_API_KEY and abuse_data:
                        abuse_color = '#d32f2f' if abuse_score >= 75 else '#f57c00' if abuse_score >= 50 else '#fbc02d' if abuse_score >= 25 else '#4caf50'
                        popup_html += f"""
                        <hr style="margin: 10px 0;">
                        <p><b style="color: {abuse_color};">Abuse Score:</b> <span style="color: {abuse_color}; font-weight: bold;">{abuse_score}%</span></p>
                        <p><b>Total Reports:</b> {total_reports}</p>
                        <p><b>Usage Type:</b> {usage_type}</p>
                        """
                        if is_tor:
                            popup_html += '<p><b style="color: #9c27b0;">[TOR] Tor Exit Node</b></p>'
                    
                    popup_html += """
                    </div>
                    """
                    
                    # Determine marker color based on abuse score
                    if IP_ABUSE_API_KEY and abuse_data:
                        if abuse_score >= 75:
                            marker_color = 'red'
                            marker_icon = 'exclamation-sign'
                        elif abuse_score >= 50:
                            marker_color = 'orange'
                            marker_icon = 'warning-sign'
                        elif abuse_score >= 25:
                            marker_color = 'yellow'
                            marker_icon = 'info-sign'
                        elif is_tor:
                            marker_color = 'purple'
                            marker_icon = 'question-sign'
                        else:
                            marker_color = 'green'
                            marker_icon = 'ok-sign'
                    else:
                        marker_color = 'blue'
                        marker_icon = 'info-sign'
                    
                    # Create tooltip with abuse info
                    if IP_ABUSE_API_KEY and abuse_data and abuse_score > 0:
                        tooltip_text = f"{ip} - {location['city']}, {location['country']} (Abuse: {abuse_score}%)"
                    else:
                        tooltip_text = f"{ip} - {location['city']}, {location['country']}"
                    
                    folium.Marker(
                        [location['latitude'], location['longitude']],
                        popup=folium.Popup(popup_html, max_width=350),
                        tooltip=tooltip_text,
                        icon=folium.Icon(color=marker_color, icon=marker_icon)
                    ).add_to(m)
                    markers_added += 1
            
            if markers_added == 0:
                print(f"  Warning: No valid location coordinates found. Map will be empty.")
                print(f"  IP locations found: {len(self.ip_locations)}")
                for ip, loc in list(self.ip_locations.items())[:5]:
                    print(f"    {ip}: lat={loc.get('latitude')}, lon={loc.get('longitude')}")
                # Still create the map even if empty - it's useful to see the base map
                print("  Creating empty map with no markers...")
            else:
                # Add a layer control only if we have markers
                folium.LayerControl().add_to(m)
            
            # Always save the map, even if empty
            print("  Saving map to file...")
            try:
                m.save(abs_output_file)
                print("  Save command completed.")
            except Exception as save_error:
                print(f"  ✗ ERROR during save: {save_error}")
                import traceback
                traceback.print_exc()
                # Try to create a basic HTML file as fallback
                try:
                    with open(abs_output_file, 'w', encoding='utf-8') as f:
                        f.write(f"""<!DOCTYPE html>
<html>
<head>
    <title>NetStatWiz - Network Map</title>
    <meta charset="utf-8">
    <style>
        body {{ font-family: Arial, sans-serif; padding: 20px; }}
        .error {{ color: red; }}
    </style>
</head>
<body>
    <h1>Network Map</h1>
    <p class="error">Error saving map: {save_error}</p>
    <p>IP Locations found: {len(self.ip_locations)}</p>
</body>
</html>""")
                    print(f"  Created fallback HTML file at: {abs_output_file}")
                except Exception as e3:
                    print(f"  ✗ Could not create fallback file: {e3}")
                return
            
            # Verify file was created
            if os.path.exists(abs_output_file):
                file_size = os.path.getsize(abs_output_file)
                print(f"\n✓ Map saved successfully to: {abs_output_file}")
                print(f"  File size: {file_size} bytes")
                print(f"  Markers added: {markers_added} out of {len(self.ip_locations)} IP locations")
            else:
                print(f"\n✗ ERROR: Map file was not created at {abs_output_file}")
                print("  Attempting to create fallback file...")
                # Create a basic HTML file as fallback
                try:
                    with open(abs_output_file, 'w', encoding='utf-8') as f:
                        f.write("""<!DOCTYPE html>
<html>
<head>
    <title>NetStatWiz - Network Map</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; padding: 20px; }
        .error { color: red; }
    </style>
</head>
<body>
    <h1>Network Map</h1>
    <p class="error">Error: Map file was not created by folium. Please check that folium is properly installed.</p>
    <p>IP Locations found: """ + str(len(self.ip_locations)) + """</p>
</body>
</html>""")
                    if os.path.exists(abs_output_file):
                        print(f"  ✓ Created fallback file at: {abs_output_file}")
                except Exception as e3:
                    print(f"  ✗ Could not create fallback file: {e3}")
            
        except Exception as e:
            print(f"\n✗ Error generating map: {e}")
            import traceback
            traceback.print_exc()
            # Try to create a minimal HTML file as fallback
            try:
                abs_output_file = os.path.abspath(output_file)
                with open(abs_output_file, 'w', encoding='utf-8') as f:
                    f.write("""<!DOCTYPE html>
<html>
<head>
    <title>NetStatWiz - Network Map</title>
    <style>
        body { font-family: Arial, sans-serif; padding: 20px; }
        .error { color: red; }
    </style>
</head>
<body>
    <h1>Network Map</h1>
    <p class="error">Error generating map. Please check that folium is installed and try again.</p>
    <p>Error details: """ + str(e) + """</p>
</body>
</html>""")
                print(f"  Created error placeholder file at: {abs_output_file}")
            except Exception as e2:
                print(f"  Could not create error file: {e2}")
    
    def generate_tables(self, output_file: str = "network_tables.html"):
        """Generate HTML tables with port and service information."""
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
            <title>NetStatWiz - Network Analysis</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    margin: 20px;
                    background-color: #f5f5f5;
                }
                h1 {
                    color: #333;
                }
                table {
                    border-collapse: collapse;
                    width: 100%;
                    margin: 20px 0;
                    background-color: white;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                th, td {
                    border: 1px solid #ddd;
                    padding: 12px;
                    text-align: left;
                }
                th {
                    background-color: #4CAF50;
                    color: white;
                    font-weight: bold;
                }
                tr:nth-child(even) {
                    background-color: #f2f2f2;
                }
                tr:hover {
                    background-color: #e8f5e9;
                }
                .summary {
                    background-color: #e3f2fd;
                    padding: 15px;
                    border-radius: 5px;
                    margin: 20px 0;
                }
            </style>
        </head>
        <body>
            <h1>NetStatWiz - Network Analysis Report</h1>
            <div class="summary">
                <h2>Summary</h2>
                <p><strong>Total Connections:</strong> {total_connections}</p>
                <p><strong>Unique IP Addresses:</strong> {unique_ips}</p>
                <p><strong>Unique Ports:</strong> {unique_ports}</p>
            </div>
        """
        
        # Add Security Alerts section if abuse checking was performed
        if IP_ABUSE_API_KEY and self.ip_abuse_data:
            # Count flagged IPs
            flagged_ips = []
            high_risk_ips = []
            tor_ips = []
            
            for ip, abuse_data in self.ip_abuse_data.items():
                score = abuse_data.get('abuse_confidence_score', 0)
                reports = abuse_data.get('total_reports', 0)
                is_tor = abuse_data.get('is_tor', False)
                
                # Only flag IPs with abuse score > 0% (exclude 0% scores)
                if score > 0:
                    flagged_ips.append((ip, abuse_data))
                if score >= 75:
                    high_risk_ips.append((ip, abuse_data))
                # Tor exit nodes are always a security concern, even with 0% score
                if is_tor:
                    tor_ips.append((ip, abuse_data))
            
            if flagged_ips or tor_ips:
                html_content += """
                    <div class="summary" style="background-color: #ffebee; border-left: 4px solid #f44336;">
                        <h2>[WARNING] Security Alerts - AbuseIPDB Results</h2>
                        <p><strong>Total IPs Checked:</strong> """ + str(len(self.ip_abuse_data)) + """</p>
                        <p><strong>IPs with Abuse Reports (Score &gt;0%):</strong> <span style="color: #d32f2f; font-weight: bold;">""" + str(len(flagged_ips)) + """</span></p>
                        <p><strong>High Risk IPs (Score &ge;75%):</strong> <span style="color: #d32f2f; font-weight: bold;">""" + str(len(high_risk_ips)) + """</span></p>
                        <p><strong>Tor Exit Nodes:</strong> <span style="color: #d32f2f; font-weight: bold;">""" + str(len(tor_ips)) + """</span></p>
                        <p><em>Note: IPs with 0% abuse score are excluded from abuse reports.</em></p>
                    </div>
                """
                
                # Add detailed abuse report table (only for IPs with score > 0)
                if flagged_ips:
                    html_content += """
                    <h2>[WARNING] Detailed Abuse Report (AbuseIPDB API Data - Score &gt;0%)</h2>
                    <table style="border: 2px solid #f44336;">
                        <tr style="background-color: #f44336; color: white;">
                            <th>IP Address</th>
                            <th>IP Version</th>
                            <th>Is Public</th>
                            <th>Abuse Score</th>
                            <th>Total Reports</th>
                            <th>Distinct Users</th>
                            <th>Tor Exit</th>
                            <th>Whitelisted</th>
                            <th>Usage Type</th>
                            <th>ISP</th>
                            <th>Domain</th>
                            <th>Hostnames</th>
                            <th>Country</th>
                            <th>Country Code</th>
                            <th>Last Reported</th>
                        </tr>
                """
                
                # Sort by abuse score (highest first)
                flagged_ips_sorted = sorted(flagged_ips, key=lambda x: x[1].get('abuse_confidence_score', 0), reverse=True)
                
                for ip, abuse_data in flagged_ips_sorted:
                    score = abuse_data.get('abuse_confidence_score', 0)
                    reports = abuse_data.get('total_reports', 0)
                    users = abuse_data.get('num_distinct_users', 0)
                    is_tor = abuse_data.get('is_tor', False)
                    usage_type = abuse_data.get('usage_type', 'Unknown')
                    isp = abuse_data.get('isp', 'Unknown')
                    domain = abuse_data.get('domain', 'Unknown')
                    hostnames = abuse_data.get('hostnames', [])
                    country = abuse_data.get('country_name', 'Unknown')
                    country_code = abuse_data.get('country_code', 'Unknown')
                    last_reported = abuse_data.get('last_reported_at', 'Never')
                    ip_version = abuse_data.get('ip_version', 4)
                    is_public = abuse_data.get('is_public', False)
                    is_whitelisted = abuse_data.get('is_whitelisted', False)
                    
                    # Format hostnames
                    hostnames_str = ', '.join(hostnames[:3]) if hostnames else 'None'
                    if len(hostnames) > 3:
                        hostnames_str += f" ... (+{len(hostnames) - 3} more)"
                    
                    # Color code row based on score
                    if score >= 75:
                        row_style = 'style="background-color: #ffcdd2;"'
                    elif score >= 50:
                        row_style = 'style="background-color: #ffe0b2;"'
                    elif score >= 25:
                        row_style = 'style="background-color: #fff9c4;"'
                    else:
                        row_style = ''
                    
                    html_content += f"""
                        <tr {row_style}>
                            <td><strong>{ip}</strong></td>
                            <td>IPv{ip_version}</td>
                            <td>{'Yes' if is_public else 'No'}</td>
                            <td style="font-weight: bold; color: {'#d32f2f' if score >= 75 else '#f57c00' if score >= 50 else '#fbc02d' if score >= 25 else '#000'};">{score}%</td>
                            <td>{reports}</td>
                            <td>{users}</td>
                            <td>{'[TOR] YES' if is_tor else 'No'}</td>
                            <td>{'Yes' if is_whitelisted else 'No'}</td>
                            <td>{usage_type}</td>
                            <td>{isp[:30] + '...' if len(isp) > 30 else isp}</td>
                            <td>{domain if domain != 'Unknown' else 'N/A'}</td>
                            <td>{hostnames_str if hostnames_str != 'None' else 'N/A'}</td>
                            <td>{country}</td>
                            <td>{country_code}</td>
                            <td>{last_reported}</td>
                        </tr>
                    """
                
                    html_content += "</table>"
                else:
                    html_content += """
                    <p><em>No IPs with abuse scores greater than 0% found.</em></p>
                    """
                
                # Add Tor exit nodes section if any found
                if tor_ips:
                    html_content += """
                        <h2>[WARNING] Tor Exit Nodes Detected (AbuseIPDB API)</h2>
                        <table style="border: 2px solid #9c27b0;">
                            <tr style="background-color: #9c27b0; color: white;">
                                <th>IP Address</th>
                                <th>IP Version</th>
                                <th>Abuse Score</th>
                                <th>Total Reports</th>
                                <th>Distinct Users</th>
                                <th>Usage Type</th>
                                <th>Country</th>
                                <th>Country Code</th>
                                <th>ISP</th>
                                <th>Domain</th>
                                <th>Last Reported</th>
                            </tr>
                    """
                    
                    for ip, abuse_data in tor_ips:
                        score = abuse_data.get('abuse_confidence_score', 0)
                        reports = abuse_data.get('total_reports', 0)
                        users = abuse_data.get('num_distinct_users', 0)
                        country = abuse_data.get('country_name', 'Unknown')
                        country_code = abuse_data.get('country_code', 'Unknown')
                        isp = abuse_data.get('isp', 'Unknown')
                        usage_type = abuse_data.get('usage_type', 'Unknown')
                        domain = abuse_data.get('domain', 'Unknown')
                        last_reported = abuse_data.get('last_reported_at', 'Never')
                        ip_version = abuse_data.get('ip_version', 4)
                        
                        html_content += f"""
                            <tr style="background-color: #f3e5f5;">
                                <td><strong>{ip}</strong></td>
                                <td>IPv{ip_version}</td>
                                <td style="font-weight: bold;">{score}%</td>
                                <td>{reports}</td>
                                <td>{users}</td>
                                <td>{usage_type}</td>
                                <td>{country}</td>
                                <td>{country_code}</td>
                                <td>{isp[:30] + '...' if len(isp) > 30 else isp}</td>
                                <td>{domain if domain != 'Unknown' else 'N/A'}</td>
                                <td>{last_reported}</td>
                            </tr>
                        """
                    
                    html_content += "</table>"
            else:
                html_content += """
                    <div class="summary" style="background-color: #e8f5e9;">
                        <h2>[OK] Security Status</h2>
                        <p>No abuse reports found for checked IP addresses.</p>
                    </div>
                """
        
        # Add connections table
        html_content += """
            <h2>All Connections</h2>
        """
        
        if not self.connections:
            html_content += """
                <p><em>No external connections found.</em></p>
            """
        else:
            html_content += """
            <table>
                <tr>
                    <th>Protocol</th>
                    <th>Remote IP</th>
                    <th>Remote Port</th>
                    <th>Service</th>
                    <th>State</th>
                    <th>Location</th>
            """
            
            # Add abuse columns if API key is configured
            if IP_ABUSE_API_KEY:
                html_content += """
                        <th>Abuse Score</th>
                        <th>Reports</th>
                        <th>Distinct Users</th>
                        <th>Tor</th>
                        <th>Usage Type</th>
                        <th>Domain</th>
                """
            
            html_content += """
                    </tr>
            """
            
            for conn in self.connections:
                location = self.ip_locations.get(conn['remote_ip'], {})
                location_str = f"{location.get('city', 'Unknown')}, {location.get('country', 'Unknown')}"
                service = self.get_service_name(conn['remote_port'])
                
                # Get abuse data if available
                abuse_data = self.ip_abuse_data.get(conn['remote_ip'], {})
                abuse_score = abuse_data.get('abuse_confidence_score', 0)
                total_reports = abuse_data.get('total_reports', 0)
                distinct_users = abuse_data.get('num_distinct_users', 0)
                is_tor = abuse_data.get('is_tor', False)
                usage_type = abuse_data.get('usage_type', 'Unknown')
                domain = abuse_data.get('domain', 'Unknown')
                
                # Color code based on abuse score
                if abuse_score >= 75:
                    score_color = "#ff0000"  # Red
                    score_style = f'style="background-color: {score_color}; color: white; font-weight: bold;"'
                elif abuse_score >= 50:
                    score_color = "#ff8800"  # Orange
                    score_style = f'style="background-color: {score_color}; color: white; font-weight: bold;"'
                elif abuse_score >= 25:
                    score_color = "#ffaa00"  # Yellow
                    score_style = f'style="background-color: {score_color};"'
                else:
                    score_style = ''
                
                html_content += f"""
                    <tr>
                        <td>{conn['protocol']}</td>
                        <td>{conn['remote_ip']}</td>
                        <td>{conn['remote_port']}</td>
                        <td>{service}</td>
                        <td>{conn['state']}</td>
                        <td>{location_str}</td>
                """
                
                if IP_ABUSE_API_KEY:
                    html_content += f"""
                        <td {score_style}>{abuse_score}%</td>
                        <td>{total_reports}</td>
                        <td>{distinct_users}</td>
                        <td>{'[TOR] Yes' if is_tor else 'No'}</td>
                        <td>{usage_type}</td>
                        <td>{domain if domain != 'Unknown' else 'N/A'}</td>
                    """
                
                html_content += """
                        </tr>
                """
            
            html_content += "</table>"
        
        # Add ports and services summary table
        html_content += """
            <h2>Ports and Services Summary</h2>
        """
        
        if not self.port_services:
            html_content += """
                <p><em>No ports/services data available.</em></p>
            """
        else:
            html_content += """
            <table>
                <tr>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Connection Count</th>
                    <th>IP Addresses</th>
                </tr>
            """
            
            for port in sorted(self.port_services.keys()):
                services = self.port_services[port]
                service_name = services[0]['service']
                unique_ips_for_port = set(s['ip'] for s in services)
                ip_list = ', '.join(list(unique_ips_for_port)[:5])
                if len(unique_ips_for_port) > 5:
                    ip_list += f" ... and {len(unique_ips_for_port) - 5} more"
                
                html_content += f"""
                    <tr>
                        <td>{port}</td>
                        <td>{service_name}</td>
                        <td>{len(services)}</td>
                        <td>{ip_list}</td>
                    </tr>
                """
            
            html_content += """
                </table>
            """
        
        html_content += """
        </body>
        </html>
        """
        
        # Format summary
        unique_ips = len(self.ip_locations)
        unique_ports = len(self.port_services)
        total_connections = len(self.connections)
        
        # Use replace instead of format to avoid issues with CSS curly braces
        html_content = html_content.replace('{total_connections}', str(total_connections))
        html_content = html_content.replace('{unique_ips}', str(unique_ips))
        html_content = html_content.replace('{unique_ports}', str(unique_ports))
        
        try:
            abs_output_file = os.path.abspath(output_file)
            with open(abs_output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            # Verify file was created
            if os.path.exists(abs_output_file):
                file_size = os.path.getsize(abs_output_file)
                print(f"\n✓ Tables saved successfully to: {abs_output_file}")
                print(f"  File size: {file_size} bytes")
            else:
                print(f"\n✗ ERROR: Table file was not created at {abs_output_file}")
        except Exception as e:
            print(f"\n✗ ERROR saving tables: {e}")
            import traceback
            traceback.print_exc()
    
    def print_summary(self):
        """Print a summary to console."""
        print("\n" + "="*60)
        print("NETWORK ANALYSIS SUMMARY")
        print("="*60)
        print(f"Total Connections: {len(self.connections)}")
        print(f"Unique IP Addresses: {len(self.ip_locations)}")
        print(f"Unique Ports: {len(self.port_services)}")
        
        print("\nTop Ports by Connection Count:")
        sorted_ports = sorted(self.port_services.items(), key=lambda x: len(x[1]), reverse=True)
        for port, services in sorted_ports[:10]:
            service_name = services[0]['service']
            print(f"  Port {port} ({service_name}): {len(services)} connections")
        
        print("\nTop Countries by Connection Count:")
        country_counts = defaultdict(int)
        for conn in self.connections:
            location = self.ip_locations.get(conn['remote_ip'], {})
            country = location.get('country', 'Unknown')
            country_counts[country] += 1
        
        for country, count in sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {country}: {count} connections")
        
        # Add abuse summary if API key is configured
        if IP_ABUSE_API_KEY and self.ip_abuse_data:
            flagged_count = sum(1 for data in self.ip_abuse_data.values() if data.get('abuse_confidence_score', 0) > 0)
            high_risk_count = sum(1 for data in self.ip_abuse_data.values() if data.get('abuse_confidence_score', 0) >= 75)
            tor_count = sum(1 for data in self.ip_abuse_data.values() if data.get('is_tor', False))
            
            print("\nAbuseIPDB Security Summary:")
            print(f"  Total IPs Checked: {len(self.ip_abuse_data)}")
            print(f"  IPs with Abuse Reports (Score >0%): {flagged_count}")
            print(f"  High Risk IPs (Score ≥75%): {high_risk_count}")
            print(f"  Tor Exit Nodes: {tor_count}")
            print("  Note: IPs with 0% abuse score are excluded from abuse reports.")


def display_intro():
    """Display the CyberReady ASCII art intro."""
    try:
        # Try to read from CyberReady.txt in the same directory as the script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        cyberready_path = os.path.join(script_dir, "CyberReady.txt")
        
        if os.path.exists(cyberready_path):
            with open(cyberready_path, 'r', encoding='utf-8') as f:
                ascii_art = f.read()
            print("\n" + ascii_art)
        else:
            # Fallback if file doesn't exist
            print("\n" + "="*60)
            print("CyberReady - Network Statistics Wizard")
            print("="*60)
    except Exception as e:
        # If there's any error reading the file, just print a simple header
        print("\n" + "="*60)
        print("NetStatWiz - Network Statistics Wizard")
        print("="*60)
    print()  # Extra blank line for spacing


def check_dependencies():
    """Check for required dependencies and provide installation instructions."""
    missing_deps = []
    
    if not FOLIUM_AVAILABLE:
        missing_deps.append("folium")
    if not PANDAS_AVAILABLE:
        missing_deps.append("pandas")
    
    if missing_deps:
        is_macos = platform.system() == 'Darwin'
        pip_cmd = "pip3" if is_macos else "pip"
        
        print("\n" + "="*60)
        print("⚠️  MISSING DEPENDENCIES DETECTED")
        print("="*60)
        print(f"The following packages are not installed: {', '.join(missing_deps)}")
        print(f"\nTo install all dependencies, run:")
        print(f"  {pip_cmd} install -r requirements.txt")
        print(f"\nOr install individually:")
        for dep in missing_deps:
            print(f"  {pip_cmd} install {dep}")
        print("\nNote: folium is required for map generation.")
        print("      pandas is optional but recommended for better table formatting.")
        print("="*60 + "\n")
        return False
    return True


def main():
    """Main entry point."""
    # Display ASCII art intro
    display_intro()
    
    print("="*60)
    print("NetStatWiz - Network Statistics Wizard")
    print("="*60)
    
    system_name = platform.system()
    print(f"Platform: {system_name}")
    
    # Check dependencies
    deps_ok = check_dependencies()
    if not FOLIUM_AVAILABLE:
        pip_cmd = "pip3" if system_name == "Darwin" else "pip"
        print("⚠️  Warning: folium is not installed. Map generation will be skipped.")
        print(f"   Install with: {pip_cmd} install folium\n")
    
    wiz = NetStatWiz()
    wiz.analyze_connections()
    
    if wiz.connections:
        wiz.print_summary()
    else:
        print("No external connections found to analyze.")
    
    # Always try to generate map and tables, even if no connections
    # (map will be empty but still created)
    print("\n" + "="*60)
    print("GENERATING REPORTS")
    print("="*60)
    
    print("\nGenerating map...")
    try:
        wiz.generate_map()
    except Exception as e:
        print(f"✗ Error generating map: {e}")
        import traceback
        traceback.print_exc()
    
    print("\nGenerating tables...")
    try:
        wiz.generate_tables()
    except Exception as e:
        print(f"✗ Error generating tables: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "="*60)
    print("Analysis complete!")
    print("="*60)
    
    # Verify files were created
    map_file = os.path.abspath("network_map.html")
    table_file = os.path.abspath("network_tables.html")
    
    print("\nFiles generated:")
    if os.path.exists(map_file):
        map_size = os.path.getsize(map_file)
        print(f"  ✓ network_map.html (interactive map) - {map_size} bytes")
    else:
        print(f"  ✗ network_map.html - NOT FOUND")
    
    if os.path.exists(table_file):
        table_size = os.path.getsize(table_file)
        print(f"  ✓ network_tables.html (detailed tables) - {table_size} bytes")
    else:
        print(f"  ✗ network_tables.html - NOT FOUND")
    
    print("\nThank you for using NetStatWiz!")
    print("Visit cyberready.world for more tools and resources.")


if __name__ == "__main__":
    main()
