import json
import os
import asyncio
from openai import OpenAI
from mcp import ClientSession, StdioServerParameters
from datetime import datetime, UTC
import argparse
from mcp.client.stdio import stdio_client
import base64

client = OpenAI()

# Context variables for local folder evidence [cite: 244, 259]
current_folder_events = ""
current_folder_alerts = ""

stats = {
    "total": 0, 
    "correct": 0, 
    "incorrect": 0,
    "total_input_tokens": 0,
    "total_time_seconds": 0,
    "total_output_tokens": 0,
    "use_cases": {}  # Format: {"usecase1": {"input": 0, "output": 0, "count": 0}}
}

def encode_image(image_path):
    with open(image_path, "rb") as image_file:
        return base64.b64encode(image_file.read()).decode('utf-8')

def print_summary():
    accuracy = (stats["correct"] / stats["total"] * 100) if stats["total"] > 0 else 0
    print("\n" + "="*40)
    print(f"TRIAGE SUMMARY")
    print(f"Total processed: {stats['total']}")
    print(f"Correct: {stats['correct']} | Incorrect: {stats['incorrect']}")
    print(f"Accuracy: {accuracy:.2f}%")
    print("-" * 40)
    
    # Calculate Overall Averages
    if stats["total"] > 0:
        avg_in = stats["total_input_tokens"] / stats["total"]
        avg_out = stats["total_output_tokens"] / stats["total"]
        avg_time = stats["total_time_seconds"] / stats["total"]
        print(f"  Avg Time: {avg_time:.2f} sec")
        print(f"OVERALL AVG TOKENS PER ALERT:")
        print(f"  Input:  {avg_in:.2f}")
        print(f"  Output: {avg_out:.2f}")
    
    print("-" * 40)
    print("AVERAGES PER USE CASE (Subfolder):")
    for uc, data in stats["use_cases"].items():
        if data["count"] > 0:
            u_avg_in = data["input"] / data["count"]
            u_avg_out = data["output"] / data["count"]
            u_avg_time = data["time"] / data["count"]
            print(f"  [{uc}] ({data['count']} alerts):")
            print(f"    Avg Input:  {u_avg_in:.2f}")
            print(f"    Avg Output: {u_avg_out:.2f}")
            print(f"    Avg Time:   {u_avg_time:.2f} sec")
    print("="*40 + "\n")

def write_debug(root_path, text):
    debug_path = os.path.join(root_path, "debug.log")
    with open(debug_path, "a", encoding="utf-8") as f:
        f.write(text + "\n\n")

def get_recent_events():
    return current_folder_events if current_folder_events else "No recent events found."

def get_recent_similar_alerts():
    return current_folder_alerts if current_folder_alerts else "No recent similar alerts found."

async def select_playbook(alert_data, playbook_dir, llm_model="gpt-5-mini"):
    """Round 1: Let the LLM choose the correct JSON file based on summaries."""
    playbook_summaries = []
    
    # Collect name and description from every json in the playbook folder
    for filename in os.listdir(playbook_dir):
        if filename.endswith(".json"):
            with open(os.path.join(playbook_dir, filename), "r", encoding="utf-8") as f:
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
        model=llm_model, 
        messages=[{"role": "user", "content": prompt}]
    )

    usage = response.usage
    return response.choices[0].message.content.strip(), usage.prompt_tokens, usage.completion_tokens

async def soc_analyst_role(alert_json, playbook_content, playbook_filename, mcp_session, root_path, image_path=None, general_mode=False, llm_model="gpt-5-mini"):

    total_in = 0
    total_out = 0

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
        "but only if they are truly needed, make sense, and provide actionable value for a client or a SOC analyst solving the ticket in a system like JIRA. "
        "Keep all fields single-level (no nested objects inside extra fields). "
        "All keys inside investigation_notes must be written in clear, regular English with spaces "
        "(e.g., 'IP Reputation Score', not snake_case or underscored keys). "
        "The Description should summarize what happened and the key observations clearly in full sentences, "
        "written as if a Tier 1 SOC analyst is reporting it, with a natural human-written tone. "
        "It should be between 2 and 4 brief sentences that are not too long, covering all main information. "
        "Remember that Description field is a MUST for the investigation notes and that it should not use first person (e.g., 'I classified this alert as HP'). "
        "In addition to summarizing, the Description should provide reasoning for why the alert is considered Low Priority (LP) or High Priority (HP), "
        "without explicitly mentioning playbooks or SOPs. "
        "There is no need to include remediation actions in the Description. "
        "Make sure to contextualize the alert properly based on all evidence provided, including any recent events or similar past alerts. "
        "If certain fields are missing from the alert, you do not need to include them in the investigation notes or use placeholders like 'none'. Likewise, there is no need to mention these missing fields in the description. "
        "Some alerts may not have specific fields as they differ. There is no need to say that 'there is no this or that' in the description, if they are missing from the alert json. "
        "Output the final JSON in a readable, beautified format with proper indentation, not as a single-line minified string."
    )

    # Construct the user content dynamically
    user_content = [
        {
            "type": "text", 
            "text": f"Playbook: {json.dumps(playbook_content)}\nAlert: {json.dumps(alert_json)}"
        }
    ]

    # 2. Check if an EVIDENCE image exists in the alert folder
    if image_path and os.path.exists(image_path):
        # A. Encode and add the Evidence Screenshot
        base64_evidence = encode_image(image_path)
        user_content.append({
            "type": "text",
            "text": "EVIDENCE SCREENSHOT: This was captured from the suspicious domain."
        })
        user_content.append({
            "type": "image_url",
            "image_url": {"url": f"data:image/jpeg;base64,{base64_evidence}"}
        })

        # B. ONLY if the evidence exists, add the REFERENCE logo for comparison
        ref_logo_path = "vitalis_icon.jpg"
        if os.path.exists(ref_logo_path):
            base64_ref = encode_image(ref_logo_path)
            user_content.append({
                "type": "text",
                "text": "REFERENCE LOGO: This is the legitimate brand logo. Use this to check for impersonation or unauthorized use in the evidence screenshot."
            })
            user_content.append({
                "type": "image_url",
                "image_url": {"url": f"data:image/jpeg;base64,{base64_ref}"}
            })
            
    tools = [
        {"type": "function", "function": {"name": "check_ip_reputation", "parameters": {"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]}}},
        {"type": "function", "function": {"name": "check_hash_reputation", "parameters": {"type": "object", "properties": {"hash": {"type": "string"}}, "required": ["hash"]}}},
        {"type": "function", "function": {"name": "get_domain_age", "parameters": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]}}},
        {"type": "function", "function": {"name": "lookup_users", "parameters": {"type": "object", "properties": {"emails": {"type": "array", "items": {"type": "string"}}}, "required": ["emails"]}}},
        {"type": "function", "function": {"name": "get_recent_events", "parameters": {"type": "object", "properties": {}}}},
        {"type": "function", "function": {"name": "get_recent_similar_alerts", "parameters": {"type": "object", "properties": {}}}}
    ]

    if general_mode:
        system_instruction = (
            f"You are a Tier-1 SOC Analyst. Output JSON only matching this structure: {json.dumps(template_guide)}\n\n"
            f"Note: {template_note}\n\n"
            "GENERAL TRIAGE GUIDANCE:\n"
            "Weigh all available evidence together. No single factor should determine the outcome. Consider how the indicators interact and whether the overall picture is consistent with legitimate activity or suspicious behavior.\n\n"
            "Classify as High Priority (HP) if the alert represents a legitimate threat, requires further investigation, or warrants escalation — this includes notifying senior analysts or the client.\n"
            "Classify as Low Priority (LP) if the activity is a false positive or represents authorized behavior that requires no further action.\n\n"
            "TOOL USAGE & PURPOSE:\n"
            "Use the following tools if necessary and if the alert contains the relevant data points:\n"
            "- 'check_ip_reputation': Use this to check if a source or destination IP is known for malicious activity.\n"
            "- 'check_hash_reputation': Use this to verify if a file hash is associated with known malware.\n"
            "- 'get_domain_age': Use this to check if a domain was recently created, which is a common indicator of phishing or C2 infrastructure.\n"
            "- 'lookup_users': Use this to verify if an email address belongs to an internal employee and check their organizational role.\n"
            "- 'get_recent_events': Use this to check for recent logs which happened before the alert timestamp from same entity.\n"
            "- 'get_recent_similar_alerts': Use this to see if the same or similar activity has been flagged before from the same entity or in the broader environment, and how it was previously resolved.\n\n"
            "Return ONLY the JSON object."
        )
    else:
        system_instruction = f"You are a Tier-1 SOC Analyst. Output JSON only: {json.dumps(template_guide)}\n\nNote: {template_note}"

    messages = [
        {"role": "system", "content": system_instruction},
        {"role": "user", "content": user_content}
    ]

    write_debug(
        os.getcwd(),
        "[SOC ANALYST PROMPT]\n" + json.dumps(messages, indent=2)
    )
    # Initial call
    response = client.chat.completions.create(model=llm_model, messages=messages,tools=tools)
    total_in += response.usage.prompt_tokens
    total_out += response.usage.completion_tokens
    msg = response.choices[0].message

    # Keep responding until no more tool calls
    while msg.tool_calls:
        # 1. Append the model's request to the history
        messages.append(msg)

        # Define which tools live on the MCP server to avoid crashing on hallucinations
        mcp_tool_whitelist = ["check_ip_reputation", "check_hash_reputation", "lookup_users", "get_domain_age"]

        for tc in msg.tool_calls:
            f_name = tc.function.name
            f_args = json.loads(tc.function.arguments) if tc.function.arguments else {}

            write_debug(root_path, f"[TOOL CALL]\nTool: {f_name}\nArguments: {json.dumps(f_args)}")
            
            # 2. Merged Routing Logic
            if f_name in mcp_tool_whitelist:

                # Call the MCP server only for whitelisted tools
                try:
                    mcp_res = await mcp_session.call_tool(f_name, arguments=f_args)
                    tool_output = mcp_res.content[0].text
                except Exception as e:
                    tool_output = f"Error calling MCP tool: {str(e)}"
            
            elif f_name == "get_recent_events":
                tool_output = get_recent_events()
            
            elif f_name == "get_recent_similar_alerts":
                tool_output = get_recent_similar_alerts()
            
            else:
                # This handles hallucinated tool names
                tool_output = f"Error: The tool '{f_name}' is not available. Please use only provided tools."

            write_debug(root_path, f"[TOOL RESPONSE]\n{tool_output}")

            # 3. Append the tool result as a 'tool' role message
            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "name": f_name,
                "content": str(tool_output)
            })

        # 4. Call the model again with the updated message history
        response = client.chat.completions.create(model=llm_model, messages=messages, tools=tools)
        total_in += response.usage.prompt_tokens
        total_out += response.usage.completion_tokens
        msg = response.choices[0].message

    # Done, return the final content
    write_debug(root_path, "[FINAL LLM OUTPUT]\n" + msg.content)
    return msg.content, total_in, total_out

async def process_dataset(root_dir, playbook_dir, mcp_session, general_mode=False, llm_model="gpt-5-mini"):
    global current_folder_events, current_folder_alerts, stats
    
    for root, dirs, files in os.walk(root_dir):
        if "alert.json" in files:
            # --- NEW: Identify the Use Case (Folder Name) ---
            # Splits the path and picks the folder name immediately under 'alerts'
            parts = os.path.normpath(root).split(os.sep)
            try:
                # Assuming root_dir is 'alerts', parts[1] is the use case
                use_case = parts[parts.index(os.path.basename(root_dir)) + 1]
            except (ValueError, IndexError):
                use_case = "unclassified"

            if use_case not in stats["use_cases"]:
                stats["use_cases"][use_case] = {
                    "input": 0,
                    "output": 0,
                    "count": 0,
                    "time": 0   # NEW
                }

            this_alert_in = 0
            this_alert_out = 0
            alert_start_time = datetime.now(UTC)

            debug_path = os.path.join(root, "debug.log")
            with open(debug_path, "w", encoding="utf-8") as f:
                f.write(f"=== DEBUG SESSION START: {datetime.now(UTC).isoformat()} UTC ===\n\n")

            with open(os.path.join(root, "alert.json"), "r", encoding="utf-8") as f:
                alert_data = json.load(f)
            
            # --- ROUND 1: Selection Logic (UPDATED to capture tokens) ---
            playbook_content = None
            pb_filename = "General Triage (No Playbook)"

            if not general_mode:
                # Capture the three return values: filename, input_tokens, output_tokens
                raw_pb_filename, in_t, out_t = await select_playbook(alert_data, playbook_dir, llm_model=llm_model)
                this_alert_in += in_t
                this_alert_out += out_t
                
                pb_filename = raw_pb_filename.strip().replace("'", "").replace('"', "")
                print(f"--- Decided on Playbook: {pb_filename} for {root} ---")
                
                pb_path = os.path.join(playbook_dir, pb_filename)
                if os.path.exists(pb_path):
                    with open(pb_path, "r", encoding="utf-8") as f:
                        playbook_content = json.load(f)
            else:
                print(f"--- General Triage Mode: Skipping playbook selection for {root} ---")

            write_debug(root, f"[PLAYBOOK SELECTION]\nAlert Name: {alert_data.get('alert_name')}\nSelected Playbook: {pb_filename}")

            # Load local evidence (keeping your existing logic)
            current_folder_events = (open(os.path.join(root, "recent_events.json"), "r", encoding="utf-8", errors="replace").read() if "recent_events.json" in files else "")
            current_folder_alerts = (open(os.path.join(root, "recent_alerts.json"), "r", encoding="utf-8", errors="replace").read() if "recent_alerts.json" in files else "")

            image_file = None
            for f in files:
                if f.lower().endswith(('.png', '.jpg', '.jpeg')):
                    image_file = os.path.join(root, f)
                    break

            # --- ROUND 2: Triage (UPDATED to capture tokens) ---
            result, in_t, out_t = await soc_analyst_role(
                alert_data, playbook_content, pb_filename, mcp_session, root, image_file, general_mode=general_mode, llm_model=llm_model
            )
            this_alert_in += in_t
            this_alert_out += out_t
            alert_end_time = datetime.now(UTC)
            alert_duration = (alert_end_time - alert_start_time).total_seconds()

            stats["total_input_tokens"] += this_alert_in
            stats["total_output_tokens"] += this_alert_out
            stats["total_time_seconds"] += alert_duration

            stats["use_cases"][use_case]["input"] += this_alert_in
            stats["use_cases"][use_case]["output"] += this_alert_out
            stats["use_cases"][use_case]["time"] += alert_duration 
            stats["use_cases"][use_case]["count"] += 1
            
            print(
                f"📊 {os.path.basename(root)} | "
                f"Input: {this_alert_in} | "
                f"Output: {this_alert_out} | "
                f"Time: {alert_duration:.2f} sec"
            )

            #  Write token usage to a file in the folder ---
            with open(os.path.join(root, "token_usage.json"), "w", encoding="utf-8") as f:
                json.dump({
                    "input_tokens": this_alert_in,
                    "output_tokens": this_alert_out,
                    "time_seconds": alert_duration,
                    "use_case": use_case
                }, f, indent=2)

            # --- CLEANUP AND CLASSIFICATION (Original Logic) ---
            clean_result = result.strip()
            if clean_result.startswith("```json"):
                clean_result = clean_result.replace("```json", "", 1).replace("```", "", 1).strip()
            elif clean_result.startswith("```"):
                clean_result = clean_result.replace("```", "", 2).strip()

            try:
                parsed_result = json.loads(clean_result)
            except json.JSONDecodeError as e:
                print(f"❌ FAILED TO PARSE LLM RESPONSE in {root}")
                continue 
            
            actual = parsed_result.get("classification", "").upper()
            expected = os.path.basename(os.path.dirname(root)).upper()

            if expected not in ["HP", "LP"]: expected = "UNKNOWN"

            stats["total"] += 1
            if actual == expected:
                stats["correct"] += 1
                print(f"✅ CORRECT: {alert_data.get('alert_name')} | Folder: {expected} (Got: {actual})")
            else:
                stats["incorrect"] += 1
                print(f"❌ INCORRECT: {alert_data.get('alert_name')} | Expected: {expected} (Got: {actual})")

            with open(os.path.join(root, "investigation_notes.json"), "w", encoding="utf-8") as f:
                json.dump(parsed_result, f, ensure_ascii=False, indent=2)

def parse_args():
    parser = argparse.ArgumentParser(description="SOC alert investigation runner")
    parser.add_argument("--alert-folder", default="alerts", help="Alert subfolder (default: alerts)")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--strict", action="store_true", help="Use playbooks from playbooks_strict folder")
    group.add_argument("--soft", action="store_true", help="Use playbooks from playbooks_soft folder")
    group.add_argument("--general", action="store_true", help="Bypass playbook selection and use general triage logic")

    parser.add_argument("--model", choices=["gpt-5-mini", "gpt-5-nano"], default="gpt-5-mini",
                        help="Choose which LLM model to use (default: gpt-5-mini)")

    return parser.parse_args()

async def main():
    args = parse_args()

    if args.alert_folder == "alerts":
        alert_root = "alerts"
    else:
        alert_root = os.path.join("alerts", args.alert_folder)

    if not os.path.isdir(alert_root):
        raise ValueError(f"Alert folder does not exist: {alert_root}")

    server_params = StdioServerParameters(
        command="python",
        args=["mcp_server.py"]
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            if args.strict:
                playbook_dir = "playbooks_test"
                general_mode = False

            elif args.soft:
                playbook_dir = "playbooks_test_soft"
                general_mode = False

            elif args.general:
                playbook_dir = None  # Not used
                general_mode = True

            else:
                raise ValueError("You must choose --strict, --soft, or --general")

            llm_model = args.model

            await process_dataset(
                alert_root,
                playbook_dir,
                session,
                general_mode=general_mode,
                llm_model=llm_model
            )
            print_summary()

            summary_report = {
                "run_timestamp": datetime.now(UTC).isoformat(),
                "overall_stats": {
                    "total_alerts": stats["total"],
                    "accuracy": (stats["correct"] / stats["total"] * 100) if stats["total"] > 0 else 0,
                    "avg_input_tokens": stats["total_input_tokens"] / stats["total"] if stats["total"] > 0 else 0,
                    "avg_output_tokens": stats["total_output_tokens"] / stats["total"] if stats["total"] > 0 else 0,
                    "avg_time_seconds": stats["total_time_seconds"] / stats["total"] if stats["total"] > 0 else 0
                },
                "use_case_breakdown": {}
            }

            for uc, data in stats["use_cases"].items():
                if data["count"] > 0:
                    summary_report["use_case_breakdown"][uc] = {
                        "alert_count": data["count"],
                        "avg_input": data["input"] / data["count"],
                        "avg_output": data["output"] / data["count"],
                        "avg_time_seconds": data["time"] / data["count"]
                    }

            with open("final_stats_report.json", "w", encoding="utf-8") as f:
                json.dump(summary_report, f, indent=2)
            print("📝 Final summary report saved to final_stats_report.json")

if __name__ == "__main__":
    asyncio.run(main())