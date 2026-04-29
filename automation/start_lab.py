import subprocess
import time

VBOXMANAGE = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"

VMS = {
    "ubuntu":  "Ubuntu 24.04 LTS",
    "kali":    "Kali",
    "windows": "Windows",
}

def vm_state(name):
    result = subprocess.run(
        [VBOXMANAGE, "showvminfo", name, "--machinereadable"],
        capture_output=True, text=True
    )
    for line in result.stdout.splitlines():
        if line.startswith("VMState="):
            return line.split("=")[1].strip('"')
    return "unknown"

def start_vm(name, headless=False):
    state = vm_state(name)
    if state == "running":
        print(f"  {name} already running, skipping.")
        return
    mode = "headless" if headless else "gui"
    print(f"  Starting {name} ({mode})...")
    subprocess.run([VBOXMANAGE, "startvm", name, "--type", mode], check=True)


def main():
    print("[1/4] Starting Ubuntu (headless)...")
    start_vm(VMS["ubuntu"], headless=True)

    print("[2/4] Giving Wazuh 90s to initialise...")
    for i in range(90, 0, -10):
        print(f"  {i}s remaining...", end="\r")
        time.sleep(10)
    print("  Done.              ")

    print("[3/4] Starting Windows 10...")
    start_vm(VMS["windows"], headless=False)

    print("[4/4] Starting Kali...")
    start_vm(VMS["kali"], headless=False)

    print("\nLab is up.")
    print("  Dashboard : https://192.168.56.10")
    print("  User      : admin")

if __name__ == "__main__":
    main()
