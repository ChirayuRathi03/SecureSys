# SecureSys

**SecureSys** is a security audit tool designed for automated verification of system configurations and compliance, particularly focusing on the Linux security settings following CIS Standards. It also implements Webserver and Databse security. The tool helps ensure that systems are configured securely, supporting administrators with automated checks against security benchmarks.

## Features

- Verifies system configuration settings related to user and desktop management.
- Checks for compliance with security policies like automount settings, idle delays, and lock delays.
- Provides an easy-to-use interface for outputting pass/fail results for each audit check.

---

## Getting Started

### Prerequisites

SecureSys requires:
- **Python 3.x**
- **Linux environment** (with GNOME Desktop Manager installed if auditing GNOME settings)
- **Admin privileges** (for configuration and system checks)

Ensure the required Python packages are installed by running:

```bash
pip install -r requirements.txt
'''
Installation
To clone and set up SecureSys:

Clone this repository:
git clone https://github.com/ChirayuRathi03/SecureSys.git
cd SecureSys
Install dependencies:

bash
Copy code
pip install -r requirements.txt

Usage
SecureSys performs a range of security audits to verify compliance. Follow these steps to run the tool:

Running the audit: From the project root directory, execute the main script:

bash
Copy code
python main.py
Interpreting Results: Results will display pass/fail for each audit check, with details on any failed configuration.

Customizing Audits: To add or modify checks, update the Python scripts in the modules/ directory.

Example
bash
Copy code
python main.py
This command will start the audit process and display results for each configuration check on the console.

Why Use SecureSys?
SecureSys simplifies the process of security compliance by automating system configuration audits. It is particularly useful for:

System Administrators: Automate routine security checks, saving time and reducing manual errors.
Compliance Officers: Quickly verify systems against internal or external security standards.
IT Managers: Ensure that desktop environments and user settings comply with security policies.
Contributing
Feel free to submit issues or pull requests. We welcome contributions that help improve the tool’s functionality, usability, and compliance coverage.

Support
For any questions or issues, please contact Chirayu Rathi.
