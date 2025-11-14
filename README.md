# NetStatWiz - Network Statistics Wizard

A tool to analyze network connections, visualize IP locations on a map, and display ports and services in tables.

## Features

- Analyze network connections using `netstat`
- Geolocate IP addresses
- Generate interactive maps showing connection locations
- Create detailed HTML tables with connection information
- Cross-platform support (Windows and macOS)

## Requirements

- Python 3.6 or higher
- Network connectivity for IP geolocation

## Installation

1. Install required dependencies:

```bash
pip3 install -r requirements.txt
```

Or install individually:

```bash
pip3 install folium
pip3 install pandas  # Optional but recommended
```

**Note:** On macOS, you may need to use `pip3` instead of `pip`.

## Usage

Run the script:

```bash
python NetWizzMAC.py
```

The program will:
1. Run `netstat` to gather network connections
2. Parse and filter external connections
3. Get geolocation data for unique IP addresses
4. Generate `network_map.html` (interactive map)
5. Generate `network_tables.html` (detailed tables)

## Output Files

- `network_map.html` - Interactive map showing IP locations (requires folium)
- `network_tables.html` - Detailed tables with connection information

## Notes

- The program respects API rate limits (1.5 seconds between IP lookups)
- Only external (non-private) IP addresses are analyzed
- Map generation requires the `folium` package

