import subprocess
import time

VBOXMANAGE = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"

VMS = {
    "windows": "Windows",
    "kali":    "Kali",
    "ubuntu":  "Ubuntu 24.04 LTS",
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

def shutdown_vm(name):
    state = vm_state(name)
    if state != "running":
        print(f"  {name} is not running, skipping.")
        return
    print(f"  Sending shutdown to {name}...")
    subprocess.run([VBOXMANAGE, "controlvm", name, "acpipowerbutton"])

def wait_for_off(name, timeout=60):
    start = time.time()
    while time.time() - start < timeout:
        if vm_state(name) in ("poweroff", "saved", "aborted"):
            print(f"  {name} is off.")
            return True
        time.sleep(3)
    print(f"  {name} did not shut down in time — forcing off.")
    subprocess.run([VBOXMANAGE, "controlvm", name, "poweroff"])
    return False

def main():
    print("[1/3] Shutting down Windows...")
    shutdown_vm(VMS["windows"])
    wait_for_off(VMS["windows"])

    print("[2/3] Shutting down Kali...")
    shutdown_vm(VMS["kali"])
    wait_for_off(VMS["kali"])

    print("[3/3] Shutting down Ubuntu (Wazuh)...")
    shutdown_vm(VMS["ubuntu"])
    wait_for_off(VMS["ubuntu"])

    print("\nLab is down.")

if __name__ == "__main__":
    main()
