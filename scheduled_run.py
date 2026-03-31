import subprocess
import time
import os
import sys

log_folder = "logs"
os.makedirs(log_folder, exist_ok=True)

main_commands = [
    ("general", "gpt-5-nano"),
    ("soft", "gpt-5-nano"),
    ("strict", "gpt-5-nano"),
    ("general", "gpt-5-mini"),
    ("soft", "gpt-5-mini"),
    ("strict", "gpt-5-mini")
]

file_extractor_cmd = "python -u file_extractor.py"

wait_seconds = 5

env = os.environ.copy()
env["PYTHONUTF8"] = "1"
env["PYTHONUNBUFFERED"] = "1"

for mode, model in main_commands:
    cmd = f"python -u main.py --{mode} --model {model}"
    log_file_path = os.path.join(log_folder, f"{mode}_{model}.log")

    print(f"\n [STARTING] {cmd}")
    print(f" Logging to: {log_file_path}\n" + "-"*30)

    with open(log_file_path, "w", encoding="utf-8") as log_file:
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, 
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            bufsize=1
        )

        if process.stdout:
            for line in process.stdout:
                sys.stdout.write(line)     
                sys.stdout.flush()         
                log_file.write(line)
                log_file.flush()           

        process.wait()

    if process.returncode != 0:
        print(f"\n Command failed with return code {process.returncode}")
    else:
        print(f"\n Finished: {cmd}")

    time.sleep(1)

    print(f"Running extractor: {file_extractor_cmd}")
    process_fe = subprocess.run(file_extractor_cmd, shell=True, env=env)
    
    if process_fe.returncode != 0:
        print(f"file_extractor.py failed after {mode}_{model}")
    
    print(f"\n Waiting {wait_seconds} seconds before next task...")
    time.sleep(wait_seconds)

print("\n All tasks in the queue have been completed.")