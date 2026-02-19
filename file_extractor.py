import os
import shutil
from datetime import datetime

def export_soc_results(source_root="alerts", export_base="exported_results"):
    # Create a unique timestamped folder for this export session
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    export_dir = os.path.join(export_base, f"export_{timestamp}")
    
    files_moved = 0
    print(f"--- Starting Export to: {export_dir} ---")

    for root, dirs, files in os.walk(source_root):
        # We are looking for these specific files
        targets = ["debug.log", "investigation_notes.json"]
        
        for filename in files:
            if filename in targets:
                # Construct a unique destination name based on the folder path
                # Example: alerts/DNS_Tunneling/HP/alert-1/debug.log 
                # becomes: exported_results/export_timestamp/DNS_Tunneling_HP_alert-1_debug.log
                
                relative_path = os.path.relpath(root, source_root)
                path_prefix = relative_path.replace(os.sep, "_")
                new_filename = f"{path_prefix}_{filename}"
                
                source_file = os.path.join(root, filename)
                destination_file = os.path.join(export_dir, new_filename)

                # Ensure destination directory exists
                os.makedirs(export_dir, exist_ok=True)

                # Move the file (change to shutil.copy if you want to keep originals in place)
                try:
                    shutil.move(source_file, destination_file)
                    files_moved += 1
                except Exception as e:
                    print(f"Error moving {source_file}: {e}")

    print(f"--- Export Complete! Moved {files_moved} files. ---")

if __name__ == "__main__":
    export_soc_results()