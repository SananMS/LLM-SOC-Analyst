import json
import sys
import os

# Fields to exclude from the "details" section (handled separately)
HEADER_FIELDS = {"Alert ID", "Start Time", "Source IP", "Destination IP", "Alert Name"}
FOOTER_FIELDS = {"Description"}

def format_note(data: dict) -> str:
    notes = data.get("investigation_notes", {})
    classification = data.get("classification", "").strip().upper()

    lines = []

    # ── Header block ─────────────────────────────────────────────
    alert_id = notes.get("Alert ID", "N/A")
    start_time = notes.get("Start Time", "N/A")
    source_ip = notes.get("Source IP")
    destination_ip = notes.get("Destination IP")
    alert_name = notes.get("Alert Name", "N/A")

    lines.append(alert_id)
    lines.append("")
    lines.append(f"Start Time: {start_time}")

    if source_ip:
        lines.append(f"Source IP: {source_ip}")
    if destination_ip:
        lines.append(f"Destination IP: {destination_ip}")

    lines.append("")
    lines.append(f"Alert Name: {alert_name}")
    lines.append("")

    # ── Details block (everything else except Description) ───────
    skip_fields = HEADER_FIELDS | FOOTER_FIELDS
    for key, value in notes.items():
        if key in skip_fields:
            continue
        lines.append(f"{key}: {value}")

    lines.append("")

    # ── Description ──────────────────────────────────────────────
    description = notes.get("Description")
    if description:
        lines.append(f"Description: {description}")
        lines.append("")

    # ── Classification ───────────────────────────────────────────
    lines.append(f"Classification: {classification}")

    return "\n".join(lines)


def process_file(input_path: str, output_path: str = None):
    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    formatted = format_note(data)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(formatted)
        print(f"Saved to: {output_path}")
    else:
        print(formatted)


def process_folder(folder_path: str, output_folder: str = None):
    """Process all investigation_notes.json files recursively in a folder."""
    for root, dirs, files in os.walk(folder_path):
        for filename in files:
            if filename == "investigation_notes.json":
                input_path = os.path.join(root, filename)

                if output_folder:
                    # Preserve subfolder structure in output
                    rel_path = os.path.relpath(root, folder_path)
                    out_dir = os.path.join(output_folder, rel_path)
                    os.makedirs(out_dir, exist_ok=True)
                    output_path = os.path.join(out_dir, "investigation_note.txt")
                else:
                    output_path = os.path.join(root, "investigation_note.txt")

                with open(input_path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                formatted = format_note(data)

                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(formatted)

                print(f"Processed: {input_path} → {output_path}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  Single file:  python format_investigation_note.py <input.json> [output.txt]")
        print("  Folder:       python format_investigation_note.py <folder> [output_folder]")
        sys.exit(1)

    input_arg = sys.argv[1]
    output_arg = sys.argv[2] if len(sys.argv) > 2 else None

    if os.path.isdir(input_arg):
        process_folder(input_arg, output_arg)
    else:
        process_file(input_arg, output_arg)