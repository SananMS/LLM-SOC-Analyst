import subprocess
import time
import os
import sys

# Folder to store logs
log_folder = "logs"
os.makedirs(log_folder, exist_ok=True)

# Define main.py commands with labels for logs
main_commands = [
    ("general", "gpt-5-nano"),
    ("soft", "gpt-5-nano"),
    ("strict", "gpt-5-nano"),
    ("general", "gpt-5-mini"),
    ("soft", "gpt-5-mini"),
    ("strict", "gpt-5-mini")
]

# File extractor command
file_extractor_cmd = "python -u file_extractor.py"

# Wait seconds between commands
wait_seconds = 5

# Setup environment for UTF-8
env = os.environ.copy()
env["PYTHONUTF8"] = "1"
env["PYTHONUNBUFFERED"] = "1"

for mode, model in main_commands:
    # Added -u for unbuffered output to ensure live streaming
    cmd = f"python -u main.py --{mode} --model {model}"
    log_file_path = os.path.join(log_folder, f"{mode}_{model}.log")

    print(f"\n🚀 [STARTING] {cmd}")
    print(f"📝 Logging to: {log_file_path}\n" + "-"*30)

    # Open log file and start process
    with open(log_file_path, "w", encoding="utf-8") as log_file:
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, # Merges error and standard output
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            bufsize=1 # Line buffered
        )

        # Stream live to terminal and write to log file simultaneously
        if process.stdout:
            for line in process.stdout:
                sys.stdout.write(line)      # More reliable for live streaming than print()
                sys.stdout.flush()          # Force terminal update
                log_file.write(line)
                log_file.flush()            # Force file write update

        process.wait()

    if process.returncode != 0:
        print(f"\n⚠️ Command failed with return code {process.returncode}")
    else:
        print(f"\n✅ Finished: {cmd}")

    # Small pause before extractor
    time.sleep(1)

    # Run file_extractor after each main.py
    print(f"🗂 Running extractor: {file_extractor_cmd}")
    # Using run() here is fine as we just want to wait for it to finish
    process_fe = subprocess.run(file_extractor_cmd, shell=True, env=env)
    
    if process_fe.returncode != 0:
        print(f"⚠️ file_extractor.py failed after {mode}_{model}")
    
    print(f"\n⏳ Waiting {wait_seconds} seconds before next task...")
    time.sleep(wait_seconds)

print("\n✨ All tasks in the queue have been completed.")