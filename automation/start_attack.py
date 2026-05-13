import subprocess
import time

VBOXMANAGE = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"

VMS = {
    "kali":    "Kali",
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
    print("Starting Kali...")
    start_vm(VMS["kali"], headless=False)

if __name__ == "__main__":
    main()
