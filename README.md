# SecureSys

**SecureSys** is a security audit tool designed for automated configuration and verification of CIS standards, particularly focusing on the Linux security settings (RHEL8, RHEL9, RL8, RL9, and OL9). It also implements Webserver and Databse security. The tool helps ensure that systems are configured securely, supporting administrators with automated checks against CIS benchmarks.

## Features

- Verifies system configuration settings related to user and desktop management.
- Checks for compliance with security policies like automount settings, idle delays, and lock delays.
- Provides an easy-to-use interface for outputting pass/fail results for each audit check.

---

## Getting Started

### Prerequisites

SecureSys requires:

- Python 3.x (3.12 and above for RHEL8 and RL8)

- Linux environment (with GNOME Desktop Manager installed if auditing GNOME settings)

- Admin privileges (for configuration and system checks)

Ensure the required Python packages are installed by running:

```bash
pip install -r requirements.txt
```

for RHEL 8 and RL 8:
```bash
pip3.12 install -r requirements.txt
```

### Installation

To clone and set up SecureSys:
1. Clone this repository:
   ```bash
   git clone https://github.com/ChirayuRathi03/SecureSys.git
   cd SecureSys
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   for RHEL8 and RL8:
   ```bash
   pip3.12 install -r requirements.txt
   ```
---

## Usage

SecureSys performs a range of security audits to verify compliance. Follow these steps to run the tool:

1. Running the audit: From the project root directory, execute the main script:
   ```bash
   python main.py
   ```
   for RHEL8 and RL8:
   ```bash
   python3.12 main.py
   ```
3. It will then ask you which mode you want to run it in, there are 3 options: Basic, Complete and Custom. 
    a. Basic Mode:  runs only the necessary configurations.
    b. Complete Mode: runs all the bash modules (to configure the settings) and then all the python modules (to verify the configurations)
    c. Custom Mode: select specific modules or ranges to run and only those will be run.
2. Interpreting Results: After both bash and python have finished executing and verifying the configurations, it will open a webserver at localhost:8050 where you can view all the failed configurations along with resource links.
3. Customizing Audits: To add or modify checks, update the Python scripts in the modules/ directory.

### Example

```bash
python main.py
```
for RHEL8 and RL8:
```bash
python3.12 main.py
```

This command will start the configuration and audit process and display results for each configuration check on the console and the webpage at localhost:8050.

---

## Why Use SecureSys?
SecureSys simplifies the process of security compliance by automating system configuration audits. It is particularly useful for:
- System Administrators: Automate routine security checks, saving time and reducing manual errors.
- Compliance Officers: Quickly verify systems against internal or external security standards.
- IT Managers: Ensure that desktop environments and user settings comply with security policies.
---

## Contributing

Feel free to submit issues or pull requests. We welcome contributions that help improve the tool’s functionality, usability, and compliance coverage.

---



## Support

For any questions or issues, please contact [Chirayu Rathi](mailto:notchirayu@gmail.com), AditiJam or siddhijani77.

---

```
