import os
os.system('pip3.12 install -r requirements.txt')
os.system('clear')

from termcolor import colored
import pandas as pd
import time
import subprocess

def get_custom_modules():
    modules = set()
    max_module = 7

    while True:
        user_input = input("Enter module numbers or ranges (e.g., '1-3' or '1,3,4' or '2'), or 'done' to finish: ").lower()
        
        if user_input == 'done':
            break
        
        parts = user_input.split(',')
        for part in parts:
            part = part.strip()
            if '-' in part:
                try:
                    start, end = map(int, part.split('-'))
                    if start < 1 or end > max_module:
                        print(f"Invalid range: {part}. Please enter numbers between 1 and {max_module}.")
                    else:
                        modules.update(range(start, end + 1))
                except ValueError:
                    print(f"Invalid range: {part}. Please use format 'start-end'.")
            else:
                try:
                    module = int(part)
                    if 1 <= module <= max_module:
                        modules.add(module)
                    else:
                        print(f"Invalid module number: {module}. Please enter numbers between 1 and {max_module}.")
                except ValueError:
                    print(f"Invalid input: {part}. Please enter a number.")
    
    return sorted(modules)


module_names = {
    1: "Initial setup",
    2: "Services",
    3: "Network and Host based firewall",
    4: "Access, Authentication and Authorization",
    5: "Logging and Auditing",
    6: "System Maintenance",
    7: "Database and Web Server Hardening"
}

main_text= r"""
  ____                           ____            
 / ___|  ___  ___ _   _ _ __ ___/ ___| _   _ ___ 
 \___ \ / _ \/ __| | | | '__/ _ \___ \| | | / __|
  ___) |  __/ (__| |_| | | |  __/___) | |_| \__ \
 |____/ \___|\___|\__,_|_|  \___|____/ \__, |___/
                                       |___/     
"""

print(colored(main_text, 'blue'))
print(colored("   Universal Hardening and Compliance Toolkit", 'blue'))

print()
print()
print("These scripts are written by:")
print("     1. Chirayu Rathi")
print("     2. Aditi Jamsandekar")
print("     3. Siddhi Jani")

print()
print()
print(colored("This script can be run in 3 modes:", 'red'))
print(colored("     1. Complete Hardening Mode (sets up everything defined in the CIS standards) and additional databse and web server hardening.", 'cyan'))
print(colored("     2. Custom Hardening Mode (Allows you to choose the hardening options you want to set up)", 'yellow'))
print(colored("     3. Basic Hardening Mode (Sets up only password complexity, logging, database hardening, antivirus, firewall, SSH, disable unecessary ports, network security)", 'green'))

print()
print()
flag = True
while flag:
    mode = input("Which mode would you like to run? [1,2,3]: ")
    try:
        mode = int(mode)
        if 1 <= mode <= 3:
            flag = False
        else:
            print("Invalid input. Please enter 1, 2, or 3.")
    except ValueError:
        print("Invalid input. Please enter a number.")

if mode == 1:
    print("Running complete hardening mode...")
    bash = ['Module1.sh', 'Module2.sh', 'Module3.sh', 'Module4.sh', 'Module5.sh', 'Module6.sh', 'Module7.sh']
    pyth = ['Module1.py', 'Module2.py', 'Module3.py', 'Module4.py', 'Module5.py', 'Module6.py']
    for x in bash:
        os.system(f'chmod 777 {x}')
        subprocess.run(['bash', '-i', x], check=True)
        os.system('clear')
    for x in pyth:
        os.system(f'python3.12 {x}')
    
elif mode == 2:
    print("Available modules:")
    print("     1. Initial setup (Filesystem, Package mgmt., Madatory Access Control, Bootloader, ptrace, coredump, Crypto Policy, Banners, GNOME)")
    print("     2. Services (Config. server services, client services, Time Synchronization, cron, at)")
    print("     3. Network (Network devices, Kernel Modules, Kernel parameters) and Host based firewall (firewalld, nftables)")
    print("     4. Access Control (SSH server, Privilege Escalation, PAM, Authselect, User Accounts), Authentication and Authorization")
    print("     5. Logging and Auditing (systemd-journal, journald, rsyslog, Log Files, auditd, Data Retention)")
    print("     6. System Maintainence (System File Permissions, User and Group Settings)")
    print("     7. Database and Web Server Hardening")

    selected_modules = get_custom_modules()
    
    if selected_modules:
        print("You selected the following modules:")
        for module in selected_modules:
            print(f"- {module_names[module]}")
    else:
        print("No modules were selected.")
    
    modules_to_run = []
    for x in selected_modules:
        x = f"Module{module}"
        modules_to_run.append(x)
    
    bash = []
    pyth = []
    for x in modules_to_run:
        bsh = f"{x}.sh"
        bash.append(bsh)
        pyt = f"{x}.py"
        pyth.append(pyt)
    
    for x in bash:
        os.system(f'chmod 777 {x}')
        subprocess.run(['bash', '-i', x], check=True)
        os.system('clear')
    for x in pyth:
        os.system(f'python3.12 {x}')
        os.system('clear')

elif mode == 3:
    print("Running basic hardening mode...")
    os.system('chmod 777 BasicConfig.sh')
    subprocess.run(['bash', '-i', 'BasicConfig.sh'], check=True)
    os.system('clear')
    os.system('python3.12 BasicConfig.py')
    
os.system("python3.12 app.py")

### Written By: 
###     1. Chirayu Rathi
###     2. Aditi Jamsandekar
###     3. Siddhi Jani
############################