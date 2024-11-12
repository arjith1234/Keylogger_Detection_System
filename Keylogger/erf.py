import psutil
import time

# Define suspicious process names
suspicious_processes = ["keylogger", "explorer", "winlogon", "svchost", "spoolsv", 
                        "system32", "taskmgr", "chrome", "vbc", "update", "malware", 
                        "remote", "darkcomet", "backdoor", "server","notepad"]


def check_for_suspicious_processes():
    print("Checking for suspicious processes...")
    detected = False
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            process_name = proc.info['name'].lower()
            for suspect in suspicious_processes:
                if suspect in process_name:
                    print(f"Suspicious Process Detected: {proc.info['name']} (PID: {proc.info['pid']})")
                    detected = True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    if not detected:
        print("No suspicious processes detected.")

if __name__ == "__main__":
    while True:
        check_for_suspicious_processes()
        time.sleep(5)  # Check every 60 seconds
       

