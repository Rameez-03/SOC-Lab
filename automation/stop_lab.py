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
        print(f"  {name} already off, skipping.")
        return False
    print(f"  Sending shutdown to {name}...")
    subprocess.run([VBOXMANAGE, "controlvm", name, "acpipowerbutton"])
    return True

def wait_for_all(names, timeout=60):
    pending = set(names)
    start = time.time()
    while pending:
        if time.time() - start > timeout:
            for name in pending:
                print(f"  {name} timed out — forcing off.")
                subprocess.run([VBOXMANAGE, "controlvm", name, "poweroff"])
            break
        for name in list(pending):
            if vm_state(name) in ("poweroff", "saved", "aborted"):
                print(f"  {name} is off.")
                pending.remove(name)
        if pending:
            time.sleep(2)

def main():
    print("Sending shutdown to all VMs...")
    targets = [name for name in VMS.values() if shutdown_vm(name)]

    if targets:
        print("\nWaiting for VMs to power off...")
        wait_for_all(targets)

    print("\nLab is down.")

if __name__ == "__main__":
    main()
