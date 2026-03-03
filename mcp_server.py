import os
import httpx
import asyncio
import base64
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
import json
# Change these imports to be explicit
from datetime import datetime, UTC

# Load API keys from .env file
load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VPNAPI_KEY = os.getenv("VPNAPI_KEY")

mcp = FastMCP("Live-SOC-Tools")

@mcp.tool()
async def get_domain_age(domain: str) -> str:
    """
    Retrieve the age of a domain from the local domain_age.json file.
    The file must be in the same folder as mcp_server.py.
    """
    file_path = os.path.join(os.path.dirname(__file__), "domain_age.json")
    
    if not os.path.exists(file_path):
        return f"Error: {file_path} not found. Ensure the database exists."

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            domain_db = json.load(f)
        
        domain_info = domain_db.get(domain.lower())

        if not domain_info:
            return f"Domain '{domain}' not found in local database. Treat as Unknown/Suspicious."

        creation_date = domain_info.get("creation_date", "Unknown")
        
        if creation_date != "Unknown":
            # Now 'datetime.strptime' works because we imported the class specifically
            creation_dt = datetime.strptime(creation_date, "%Y-%m-%d").replace(tzinfo=UTC)
            now = datetime.now(UTC)
            age_days = (now - creation_dt).days
            return f"Domain: {domain} | Created: {creation_date} | Age: {age_days} days old."
        
        return f"Domain: {domain} | Created: Unknown | Age: Unknown"

    except Exception as e:
        return f"Error reading domain_age.json: {str(e)}"
        
@mcp.tool()
async def lookup_users(emails: list[str]) -> str:
    """
    Search for user details in the local users.json file based on a list of emails.
    Comparison is case-insensitive.
    """
    file_path = os.path.join(os.path.dirname(__file__), "users.json")
    
    if not os.path.exists(file_path):
        return "Error: users.json file not found in the server directory."

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            users_db = json.load(f)
        
        if not isinstance(users_db, list):
            return "Error: users.json format is invalid. Expected a list of user objects."

        # 1. Normalize input emails to lowercase
        normalized_input_emails = [email.casefold() for email in emails]

        # 2. Filter users by comparing normalized email strings
        found_users = [
            u for u in users_db 
            if u.get("email") and u.get("email").casefold() in normalized_input_emails
        ]

        if not found_users:
            return f"No users found for emails: {', '.join(emails)}"

        return json.dumps(found_users, indent=2)

    except Exception as e:
        return f"Error reading users.json: {str(e)}"

@mcp.tool()
async def check_ip_reputation(ip: str) -> str:
    """Query AbuseIPDB and vpnapi.io for reputation, ISP, and VPN/Proxy status."""
    
    abuse_url = "https://api.abuseipdb.com/api/v2/check"
    abuse_headers = {"Accept": "application/json", "Key": ABUSE_API_KEY}
    abuse_params = {"ipAddress": ip, "verbose": "true"}
    
    # Updated to follow the vpnapi.io documentation: https://vpnapi.io/api/{IP}?key={API_KEY}
    vpnapi_url = f"https://vpnapi.io/api/{ip}"
    vpnapi_params = {"key": VPNAPI_KEY}

    async with httpx.AsyncClient() as client:
        try:
            # Concurrent requests to both APIs for SOC efficiency
            abuse_task = client.get(abuse_url, headers=abuse_headers, params=abuse_params)
            vpnapi_task = client.get(vpnapi_url, params=vpnapi_params)
            
            abuse_resp, vpnapi_resp = await asyncio.gather(abuse_task, vpnapi_task)
            
            # Process AbuseIPDB Data
            abuse_resp.raise_for_status()
            a_data = abuse_resp.json()["data"]
            score = a_data.get("abuseConfidenceScore", "N/A")
            usage_type = a_data.get("usageType", "Unknown")
            isp = a_data.get("isp", "Unknown")

            # Process vpnapi.io Data based on provided documentation
            vpnapi_resp.raise_for_status()
            v_data = vpnapi_resp.json()
            
            # Extract security flags as defined in the documentation
            security = v_data.get("security", {})
            is_vpn = security.get("vpn", False)      # Determines if IP address is a VPN
            is_proxy = security.get("proxy", False)  # Determines if IP address is a Proxy
            is_tor = security.get("tor", False)      # Determines if IP address is a Tor Node
            is_relay = security.get("relay", False)  # Determines if IP address is a Relay (ex. iCloud Private Relay)
            
            privacy_status = []
            if is_vpn: privacy_status.append("VPN")
            if is_proxy: privacy_status.append("Proxy")
            if is_tor: privacy_status.append("Tor")
            if is_relay: privacy_status.append("Relay")
            
            privacy_label = ", ".join(privacy_status) if privacy_status else "Neither VPN nor Proxy nor Tor Node nor Relay"

            # Formatted output for the LLM Analyst
            return (f"Source IP: {ip} | Abuse Confidence Score: {score}/100 | ISP: {isp} | "
                    f"Usage Type: {usage_type} | Privacy Status: {privacy_label}")
            
        except Exception as e:
            return f"Error during IP reputation check: {str(e)}"
        
@mcp.tool()
async def check_hash_reputation(hash: str) -> str:
    """Query VirusTotal for file hash reputation, name, and community score."""
    url = f"https://www.virustotal.com/api/v3/files/{hash}"
    headers = {"x-apikey": VT_API_KEY}

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers)
            if response.status_code == 404:
                return f"Hash {hash} not found in VirusTotal database."
            
            response.raise_for_status()
            data = response.json()["data"]["attributes"]
            
            # 1. Engine Analysis Stats
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            
            # 2. Community Reputation Score
            # This is a net score calculated from community votes.
            community_reputation = data.get("reputation", 0)
            
            # 3. Community Votes breakdown (Optional but helpful)
            votes = data.get("total_votes", {})
            harmless_votes = votes.get("harmless", 0)
            malicious_votes = votes.get("malicious", 0)
            
            # Extract names
            file_name = data.get("meaningful_name") or (data.get("names", ["Unknown"])[0])
            
            return (
                f"VT Results for {hash} ({file_name}):\n"
                f"  - Engines: {malicious} Malicious | {suspicious} Suspicious\n"
                f"  - Community Score: {community_reputation}\n"
                f"  - Community Votes: {malicious_votes} Malicious vs {harmless_votes} Harmless"
            )
        except Exception as e:
            return f"Error querying VirusTotal: {str(e)}"
        
if __name__ == "__main__":
    mcp.run()