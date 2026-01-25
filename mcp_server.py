import os
import httpx
import asyncio
import base64
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

# Load API keys from .env file
load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VPNAPI_KEY = os.getenv("VPNAPI_KEY")

mcp = FastMCP("Live-SOC-Tools")

@mcp.tool()
async def decode_base64(encoded_str: str) -> str:
    """Decodes a Base64 encoded string into plaintext UTF-8."""
    try:
        # Remove common PowerShell artifacts if present
        clean_str = encoded_str.strip()
        decoded_bytes = base64.b64decode(clean_str)
        # Handle potential UTF-16 encoding often used by PowerShell -encodedcommand
        try:
            return decoded_bytes.decode("utf-16")
        except UnicodeDecodeError:
            return decoded_bytes.decode("utf-8")
    except Exception as e:
        return f"Error decoding Base64: {str(e)}"

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
            return (f"Source IP: {ip} | Security Score: {score}/100 | ISP: {isp} | "
                    f"Usage Type: {usage_type} | Privacy Status: {privacy_label}")
            
        except Exception as e:
            return f"Error during IP reputation check: {str(e)}"
        
@mcp.tool()
async def check_hash_reputation(hash_val: str) -> str:
    """Query VirusTotal for file hash reputation."""
    url = f"https://www.virustotal.com/api/v3/files/{hash_val}"
    headers = {"x-apikey": VT_API_KEY}

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers)
            if response.status_code == 404:
                return f"Hash {hash_val} not found in VirusTotal database."
            
            response.raise_for_status()
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            
            return f"VT Results for {hash_val}: Malicious: {malicious} | Suspicious: {suspicious}"
        except Exception as e:
            return f"Error querying VirusTotal: {str(e)}"

if __name__ == "__main__":
    mcp.run()