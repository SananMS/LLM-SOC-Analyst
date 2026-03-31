import os
import shutil
from datetime import datetime

def export_soc_results(source_root="alerts", export_base="exported_results", final_stats_file="final_stats_report.json"):
    """
    Exports SOC alert results including final_stats_report.json into a timestamped export folder.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    export_dir = os.path.join(export_base, f"export_{timestamp}")
    os.makedirs(export_dir, exist_ok=True)
    print(f"--- Starting Export to: {export_dir} ---")

    files_moved = 0

    for root, dirs, files in os.walk(source_root):
        targets = ["debug.log", "investigation_notes.json", "token_usage.json"]

        for filename in files:
            if filename in targets:
                relative_path = os.path.relpath(root, source_root)
                path_prefix = relative_path.replace(os.sep, "_")
                new_filename = f"{path_prefix}_{filename}"

                source_file = os.path.join(root, filename)
                destination_file = os.path.join(export_dir, new_filename)

                try:
                    shutil.move(source_file, destination_file)
                    files_moved += 1
                except Exception as e:
                    print(f"Error moving {source_file}: {e}")

    if os.path.exists(final_stats_file):
        try:
            shutil.copy(final_stats_file, os.path.join(export_dir, final_stats_file))
            files_moved += 1
        except Exception as e:
            print(f"Error copying {final_stats_file} to export folder: {e}")

    print(f"--- Export Complete! Moved {files_moved} files. ---")
    print(f"final_stats_report.json copied to {export_dir}")


if __name__ == "__main__":
    export_soc_results()