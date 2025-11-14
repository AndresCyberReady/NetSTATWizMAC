# NetStatWiz - Network Statistics Wizard

A tool to analyze network connections, visualize IP locations on a map, and display ports and services in tables.

## Features

- Analyze network connections using `netstat`
- Geolocate IP addresses
- **IP Abuse Detection** - Check IP addresses against AbuseIPDB for malicious activity
- Generate interactive maps showing connection locations with abuse score indicators
- Create detailed HTML tables with connection information and abuse reports
- Cross-platform support (Windows and macOS)

## Requirements

- Python 3.6 or higher
- Network connectivity for IP geolocation
- (Optional) AbuseIPDB API key for IP abuse checking

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

## IP Abuse Detection Setup

NetStatWiz integrates with [AbuseIPDB](https://www.abuseipdb.com/) to check IP addresses for malicious activity and abuse reports.

### Getting an AbuseIPDB API Key

1. Sign up for a free account at [https://www.abuseipdb.com/](https://www.abuseipdb.com/)
2. Navigate to your account settings and generate an API key
3. The free tier allows up to 1,000 requests per day

### Configuring the API Key

1. Open `NetWizzMAC.py` in a text editor
2. Find the line: `IP_ABUSE_API_KEY = "#"`
3. Replace `"#"` with your API key:
   ```python
   IP_ABUSE_API_KEY = "your_api_key_here"
   ```

### What Gets Checked

The program automatically checks all unique external (public) IP addresses found in your network connections against AbuseIPDB. For each IP, it retrieves:

- **Abuse Confidence Score** (0-100%) - Likelihood the IP is malicious
- **Total Reports** - Number of abuse reports submitted
- **Distinct Users** - Number of unique users who reported the IP
- **Tor Exit Node Status** - Whether the IP is a known Tor exit node
- **Usage Type** - Classification (Data Center, Commercial, ISP, etc.)
- **ISP Information** - Internet Service Provider details
- **Domain & Hostnames** - Associated domain names
- **Country Information** - Geographic location data
- **Last Reported** - Most recent abuse report timestamp

### Abuse Score Filtering

- **IPs with 0% abuse score are excluded** from abuse reports (considered clean)
- Only IPs with abuse scores > 0% are shown in the "Detailed Abuse Report" section
- Tor exit nodes are always flagged as security concerns, regardless of score
- All connections are still visible in the main connections table for complete visibility

### Rate Limiting

The program respects AbuseIPDB's rate limits with a 2-second delay between API calls to avoid exceeding the free tier limit of 1,000 requests per day.

## Usage

Run the script:

```bash
python NetWizzMAC.py
```

The program will:
1. Run `netstat` to gather network connections
2. Parse and filter external connections
3. Get geolocation data for unique IP addresses
4. (If API key configured) Check IPs against AbuseIPDB for abuse reports
5. Generate `network_map.html` (interactive map with abuse indicators)
6. Generate `network_tables.html` (detailed tables with abuse reports)

## Output Files

### `network_map.html`
Interactive map showing IP locations with color-coded markers based on abuse scores:
- **Red** - High risk (abuse score ≥75%)
- **Orange** - Medium-high risk (abuse score 50-74%)
- **Yellow** - Medium risk (abuse score 25-49%)
- **Purple** - Tor exit nodes
- **Green** - Low/no abuse (score <25% or 0%)
- **Blue** - No abuse data available

Click on markers to see detailed information including abuse scores, reports, ISP, and location data.

### `network_tables.html`
Comprehensive HTML report containing:
- **Security Alerts Section** - Summary of IPs with abuse reports (score >0%)
- **Detailed Abuse Report** - Full AbuseIPDB data for flagged IPs
- **Tor Exit Nodes Table** - All detected Tor exit nodes
- **All Connections Table** - Complete connection list with abuse data columns
- **Ports and Services Summary** - Port usage statistics

**Note:** Requires `folium` package for map generation. If not installed, a basic HTML file will still be created.

## Notes

- The program respects API rate limits:
  - IP geolocation: 1.5 seconds between lookups
  - AbuseIPDB API: 2 seconds between checks (free tier: 1,000 requests/day)
- Only external (non-private) IP addresses are analyzed
- Map generation requires the `folium` package
- IP abuse checking is optional - the program works without an API key, but abuse reports won't be generated
- AbuseIPDB API calls use proper URL encoding for IPv6 addresses and handle rate limit errors gracefully

