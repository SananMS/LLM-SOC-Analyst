import json
import os
import asyncio
from openai import OpenAI
from mcp import ClientSession, StdioServerParameters
from datetime import datetime
from mcp.client.stdio import stdio_client

client = OpenAI()

# Context variables for local folder evidence [cite: 244, 259]
current_folder_events = ""
current_folder_alerts = ""

def write_debug(root_path, text):
    debug_path = os.path.join(root_path, "debug.log")
    with open(debug_path, "a", encoding="utf-8") as f:
        f.write(text + "\n\n")

def get_recent_events():
    return current_folder_events if current_folder_events else "No recent events found."

def get_recent_similar_alerts():
    return current_folder_alerts if current_folder_alerts else "No recent similar alerts found."

async def select_playbook(alert_data, playbook_dir):
    """Round 1: Let the LLM choose the correct JSON file based on summaries."""
    playbook_summaries = []
    
    # Collect name and description from every json in the playbook folder
    for filename in os.listdir(playbook_dir):
        if filename.endswith(".json"):
            with open(os.path.join(playbook_dir, filename), 'r') as f:
                pb = json.load(f)
                playbook_summaries.append({
                    "filename": filename,
                    "playbook_name": pb.get("playbook_name"),
                    "description": pb.get("description")
                })

    prompt = (
        f"Given this alert: {alert_data.get('alert_name')}\n"
        f"And these available playbooks: {json.dumps(playbook_summaries)}\n"
        "Which filename is the most appropriate to use for this investigation? "
        "Return ONLY the filename (e.g., 'suspicious_powershell.json')."
    )

    response = client.chat.completions.create(
        model="gpt-5-mini", # Or your preferred model
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content.strip()

async def soc_analyst_role(alert_json, playbook_content, playbook_filename, mcp_session, root_path):

    """Analyze alert and generate investigation notes using template as a guide"""
    template_guide = {
        "investigation_notes": {
            "Alert ID": "Unique identifier assigned to the alert within the SOC system.",
            "Start Time": "Timestamp indicating when the alert was generated.",
            "Alert Name": "Name or type of the alert as reported by the SIEM (e.g., Suspicious PowerShell Command Execution).",
            "Source IP": "IP address of the originator or user device associated with the alert.",
            "Destination IP": "Target IP address contacted or affected during the activity.",
            "Endpoint": "Hostname or device name where the alert originated.",
            "User": "Username linked to the activity or login session.",
            "Playbook Used": "Name of the investigation playbook automatically selected for analysis.",
            "Description": "Brief summary of what triggered the alert and the key observations identified during the investigation."
        },
        "classification": "LP (Low Priority) or HP (High Priority). Only write LP or HP for this part and no need for full form."
    }

    # Note to LLM
    template_note = (
        "Use the template above as a guide. If a specific field within the template guide "
        "does not exist or cannot be found in the alert evidence, do not include it in the final output. "
        "You may include up to 4-5 additional relevant keys inside investigation_notes, "
        "but only if they are truly needed, make sense, and would be useful for solving the ticket in a system like JIRA. "
        "Keep all fields single-level (no nested objects inside extra fields). "
        "All keys inside investigation_notes must be written in clear, regular English with spaces "
        "(e.g., 'IP Reputation Score', not snake_case or underscored keys). "
        "The Description should summarize what happened and the key observations clearly in full sentences, "
        "written as if a Tier 1 SOC analyst is reporting it, with a natural human-written tone. "
        "It should be between 2 and 4 brief sentences that are not too long, covering all main information. "
        "In addition to summarizing, the Description should provide reasoning for why the alert is considered Low Priority (LP) or High Priority (HP), "
        "without explicitly mentioning playbooks or SOPs. "
        "There is no need to include remediation actions in the Description. "
        "Output the final JSON in a readable, beautified format with proper indentation, not as a single-line minified string."
    )

    tools = [
        {"type": "function", "function": {"name": "check_ip_reputation", "parameters": {"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]}}},
        {"type": "function", "function": {"name": "check_hash_reputation", "parameters": {"type": "object", "properties": {"hash": {"type": "string"}}, "required": ["hash"]}}},
        {"type": "function", "function": {"name": "decode_base64", "parameters": {"type": "object", "properties": {"encoded_str": {"type": "string"}}, "required": ["encoded_str"]}}},
        {"type": "function", "function": {"name": "get_recent_events", "parameters": {"type": "object", "properties": {}}}},
        {"type": "function", "function": {"name": "get_recent_similar_alerts", "parameters": {"type": "object", "properties": {}}}}
    ]

    messages = [
        {"role": "system", "content": f"You are a Tier-1 SOC Analyst. Output JSON only: {json.dumps(template_guide)}\n\nNote: {template_note}"},
        {"role": "user", "content": f"Playbook: {json.dumps(playbook_content)}\nAlert: {json.dumps(alert_json)}"}
    ]

    write_debug(
        os.getcwd(),
        "[SOC ANALYST PROMPT]\n" + json.dumps(messages, indent=2)
    )
    response = client.chat.completions.create(model="gpt-5-mini", messages=messages, tools=tools)
    msg = response.choices[0].message

    if msg.tool_calls:
        messages.append(msg)
        for tc in msg.tool_calls:
            f_name = tc.function.name
            f_args = json.loads(tc.function.arguments)

            write_debug(
                root_path,
                f"[TOOL CALL]\nTool: {f_name}\nArguments: {json.dumps(f_args)}"
            )
            
            # Routing: MCP Server vs Local Context [cite: 259, 260]
            if f_name in ["check_ip_reputation", "check_hash_reputation", "decode_base64"]:
                # Error fix: we now have access to mcp_session passed into the function
                mcp_res = await mcp_session.call_tool(f_name, arguments=f_args)
                tool_output = mcp_res.content[0].text
                write_debug(
                    root_path,
                    f"[TOOL RESPONSE]\n{tool_output}"
                )
            else:
                if f_name == "get_recent_events":
                    tool_output = get_recent_events()
                else:
                    tool_output = get_recent_similar_alerts()

            messages.append({"tool_call_id": tc.id, "role": "tool", "name": f_name, "content": tool_output})
        
        final = client.chat.completions.create(model="gpt-5-mini", messages=messages)

        write_debug(
            root_path,
            "[FINAL LLM OUTPUT]\n" + final.choices[0].message.content
        )
        return final.choices[0].message.content
    return msg.content

async def process_dataset(root_dir, playbook_dir, mcp_session):
    global current_folder_events, current_folder_alerts
    
    for root, dirs, files in os.walk(root_dir):
        if "alert.json" in files:
            debug_path = os.path.join(root, "debug.log")
            with open(debug_path, "w", encoding="utf-8") as f:
                f.write(f"=== DEBUG SESSION START: {datetime.utcnow().isoformat()} UTC ===\n\n")

            with open(os.path.join(root, "alert.json"), 'r') as f:
                alert_data = json.load(f)
            
            # --- ROUND 1: Dynamic Selection ---
            pb_filename = await select_playbook(alert_data, playbook_dir)

            write_debug(
                root,
                f"[PLAYBOOK SELECTION]\nAlert Name: {alert_data.get('alert_name')}\nSelected Playbook: {pb_filename}"
            )

            # Clean the filename of any quotes the LLM might have added
            pb_filename = pb_filename.strip().replace("'", "").replace('"', "")

            print(f"--- Decided on Playbook: {pb_filename} for {root} ---")

            # Now this open() will work correctly
            with open(os.path.join(playbook_dir, pb_filename), 'r') as f:
                playbook_content = json.load(f)

            # Load local evidence
            current_folder_events = open(os.path.join(root, "recent_events.json")).read() if "recent_events.json" in files else ""
            current_folder_alerts = open(os.path.join(root, "recent_alerts.json")).read() if "recent_alerts.json" in files else ""

            # --- ROUND 2: Triage ---
            result = await soc_analyst_role(
                alert_data,
                playbook_content,
                pb_filename,
                mcp_session,
                root
            )
            
            with open(os.path.join(root, "investigation_notes.json"), 'w') as f:
                f.write(result)

async def main():
    # Setup connection parameters for the MCP server [cite: 259]
    server_params = StdioServerParameters(command="python", args=["mcp_server.py"])

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            # FIXED: Pass session into the dataset processor
            await process_dataset("alerts", "playbooks", session)

if __name__ == "__main__":
    asyncio.run(main())