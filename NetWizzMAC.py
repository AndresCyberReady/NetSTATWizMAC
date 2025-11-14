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
    20: "FTP Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB",
    6379: "Redis", 9200: "Elasticsearch", 27015: "Steam"
}


class NetStatWiz:
    def __init__(self):
        self.connections = []
        self.ip_locations = {}
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
                    
                    # Create popup content
                    popup_html = f"""
                    <div style="font-family: Arial; width: 200px;">
                        <h4>{ip}</h4>
                        <p><b>Location:</b> {location['city']}, {location['region']}, {location['country']}</p>
                        <p><b>ISP:</b> {location['isp']}</p>
                        <p><b>Organization:</b> {location['org']}</p>
                        <p><b>Connections:</b> {conn_count}</p>
                    </div>
                    """
                    
                    folium.Marker(
                        [location['latitude'], location['longitude']],
                        popup=folium.Popup(popup_html, max_width=300),
                        tooltip=f"{ip} - {location['city']}, {location['country']}",
                        icon=folium.Icon(color='red', icon='info-sign')
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
        
        # Add connections table
        html_content += """
            <h2>All Connections</h2>
            <table>
                <tr>
                    <th>Protocol</th>
                    <th>Remote IP</th>
                    <th>Remote Port</th>
                    <th>Service</th>
                    <th>State</th>
                    <th>Location</th>
                </tr>
        """
        
        for conn in self.connections:
            location = self.ip_locations.get(conn['remote_ip'], {})
            location_str = f"{location.get('city', 'Unknown')}, {location.get('country', 'Unknown')}"
            service = self.get_service_name(conn['remote_port'])
            
            html_content += f"""
                <tr>
                    <td>{conn['protocol']}</td>
                    <td>{conn['remote_ip']}</td>
                    <td>{conn['remote_port']}</td>
                    <td>{service}</td>
                    <td>{conn['state']}</td>
                    <td>{location_str}</td>
                </tr>
            """
        
        html_content += "</table>"
        
        # Add ports and services summary table
        html_content += """
            <h2>Ports and Services Summary</h2>
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
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"\nTables saved to {output_file}")
    
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
    print("\nGenerating map...")
    wiz.generate_map()
    
    print("\nGenerating tables...")
    wiz.generate_tables()
    
    print("\n" + "="*60)
    print("Analysis complete!")
    print("="*60)
    print("Files generated:")
    print("  - network_map.html (interactive map)")
    print("  - network_tables.html (detailed tables)")
    print(" Thank you for using NetStatWiz!")
    print(" Visit cyberready.world for more tools and resources.")


if __name__ == "__main__":
    main()
